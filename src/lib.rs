extern crate alloc;
extern crate core;

use alloc::borrow::Cow;
use core::cmp;

use bitcoin::consensus::Encodable;
use bitcoin::hashes::{hash160, ripemd160, sha1, sha256, sha256d, Hash};
use bitcoin::opcodes::{all::*, Opcode};
use bitcoin::script::{self, Instruction, Instructions, Script, ScriptBuf};
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::{self, TapLeafHash};
use bitcoin::transaction::{self, Transaction, TxOut};

#[cfg(feature = "serde")]
use serde;

#[macro_use]
mod macros;

mod utils;
use utils::ConditionStack;

mod signatures;

mod error;
pub use error::{Error, ExecError};

#[cfg(feature = "json")]
pub mod json;
#[cfg(feature = "wasm")]
mod wasm;

mod data_structures;
pub use data_structures::Stack;

/// Maximum number of non-push operations per script
const MAX_OPS_PER_SCRIPT: usize = 201;

/// Maximum number of bytes pushable to the stack
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum number of values on script interpreter stack
const MAX_STACK_SIZE: usize = 1000;

/// If this flag is set, CTxIn::nSequence is NOT interpreted as a
/// relative lock-time.
/// It skips SequenceLocks() for any input that has it set (BIP 68).
/// It fails OP_CHECKSEQUENCEVERIFY/CheckSequence() for any input that has
/// it set (BIP 112).
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// How much weight budget is added to the witness size (Tapscript only, see BIP 342).
const VALIDATION_WEIGHT_OFFSET: i64 = 50;

/// Validation weight per passing signature (Tapscript only, see BIP 342).
const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;

// Maximum number of public keys per multisig
const _MAX_PUBKEYS_PER_MULTISIG: i64 = 20;

/// Used to enable experimental script features.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Experimental {
    /// Enable an experimental implementation of OP_CAT.
    pub op_cat: bool,
}

/// Used to fine-tune different variables during execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Require data pushes be minimally encoded.
    pub require_minimal: bool, //TODO(stevenroose) double check all fRequireMinimal usage in Core
    /// Verify OP_CHECKLOCKTIMEVERIFY.
    pub verify_cltv: bool,
    /// Verify OP_CHECKSEQUENCEVERIFY.
    pub verify_csv: bool,
    /// Verify conditionals are minimally encoded.
    pub verify_minimal_if: bool,

    pub experimental: Experimental,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            require_minimal: true,
            verify_cltv: true,
            verify_csv: true,
            verify_minimal_if: true,
            experimental: Experimental { op_cat: true },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecCtx {
    Legacy,
    SegwitV0,
    Tapscript,
}

pub struct TxTemplate {
    pub tx: Transaction,
    pub prevouts: Vec<TxOut>,
    pub input_idx: usize,
    pub taproot_annex_scriptleaf: Option<(TapLeafHash, Option<Vec<u8>>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub success: bool,
    pub error: Option<ExecError>,
    pub opcode: Option<Opcode>,
    pub final_stack: Stack,
}

impl ExecutionResult {
    fn from_final_stack(ctx: ExecCtx, final_stack: Stack) -> ExecutionResult {
        ExecutionResult {
            success: match ctx {
                ExecCtx::Legacy => {
                    if final_stack.is_empty() {
                        false
                    } else if !script::read_scriptbool(&final_stack.last().unwrap()) {
                        false
                    } else {
                        true
                    }
                }
                ExecCtx::SegwitV0 | ExecCtx::Tapscript => {
                    if final_stack.len() != 1 {
                        false
                    } else if !script::read_scriptbool(&final_stack.last().unwrap()) {
                        false
                    } else {
                        true
                    }
                }
            },
            final_stack: final_stack,
            error: None,
            opcode: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExecStats {
    /// The highest number of stack items occurred during execution.
    /// This counts both the stack and the altstack.
    pub max_nb_stack_items: usize,

    /// The number of opcodes executed, plus an additional one
    /// per signature in CHECKMULTISIG.
    pub opcode_count: usize,

    /// The validation weight execution started with.
    pub start_validation_weight: i64,
    /// The current remaining validation weight.
    pub validation_weight: i64,
}

/// Partial execution of a script.
pub struct Exec {
    ctx: ExecCtx,
    opt: Options,
    tx: TxTemplate,
    result: Option<ExecutionResult>,

    sighashcache: SighashCache<Transaction>,
    script: &'static Script,
    instructions: Instructions<'static>,
    current_position: usize,
    cond_stack: ConditionStack,
    stack: Stack,
    altstack: Stack,
    last_codeseparator_pos: Option<u32>,
    // Initially set to the whole script, but updated when
    // OP_CODESEPARATOR is encountered.
    script_code: &'static Script,

    opcode_count: usize,
    validation_weight: i64,

    // runtime statistics
    stats: ExecStats,
}

impl std::ops::Drop for Exec {
    fn drop(&mut self) {
        // we need to safely drop the script we allocated
        unsafe {
            let script = core::mem::replace(&mut self.script, Script::from_bytes(&[]));
            let _ = Box::from_raw(script as *const Script as *mut Script);
        }
    }
}

impl Exec {
    pub fn new(
        ctx: ExecCtx,
        opt: Options,
        tx: TxTemplate,
        script: ScriptBuf,
        script_witness: Vec<Vec<u8>>,
    ) -> Result<Exec, Error> {
        if ctx == ExecCtx::Tapscript {
            if tx.taproot_annex_scriptleaf.is_none() {
                return Err(Error::Other("missing taproot tx info in tapscript context"));
            }

            if let Some((_, Some(ref annex))) = tx.taproot_annex_scriptleaf {
                if annex.get(0) != Some(&taproot::TAPROOT_ANNEX_PREFIX) {
                    return Err(Error::Other("invalid annex: missing prefix"));
                }
            }
        }

        // We want to make sure the script is valid so we don't have to throw parsing errors
        // while executing.
        let instructions = if opt.require_minimal {
            script.instructions_minimal()
        } else {
            script.instructions()
        };
        if let Some(err) = instructions.clone().find_map(|res| res.err()) {
            return Err(Error::InvalidScript(err));
        }

        // *****
        // Make sure there is no more possible exit path after this point!
        // Otherwise we are leaking memory.
        // *****

        // We box alocate the script to get a static Instructions iterator.
        // We will manually drop this allocation in the ops::Drop impl.
        let script = Box::leak(script.into_boxed_script()) as &'static Script;
        let instructions = if opt.require_minimal {
            script.instructions_minimal()
        } else {
            script.instructions()
        };

        //TODO(stevenroose) make this more efficient
        let witness_size =
            Encodable::consensus_encode(&script_witness, &mut bitcoin::io::sink()).unwrap();
        let start_validation_weight = VALIDATION_WEIGHT_OFFSET + witness_size as i64;

        let mut ret = Exec {
            ctx: ctx,
            result: None,

            sighashcache: SighashCache::new(tx.tx.clone()),
            script: script,
            instructions: instructions,
            current_position: 0,
            cond_stack: ConditionStack::new(),
            //TODO(stevenroose) does this need to be reversed?
            stack: Stack::from_u8_vec(script_witness),
            altstack: Stack::new(),
            opcode_count: 0,
            validation_weight: start_validation_weight,
            last_codeseparator_pos: None,
            script_code: script,

            opt: opt,
            tx: tx,

            stats: ExecStats {
                start_validation_weight: start_validation_weight,
                validation_weight: start_validation_weight,
                ..Default::default()
            },
        };
        ret.update_stats();
        Ok(ret)
    }

    //////////////////
    // SOME GETTERS //
    //////////////////

    pub fn result(&self) -> Option<&ExecutionResult> {
        self.result.as_ref()
    }

    pub fn script_position(&self) -> usize {
        self.script.len() - self.instructions.as_script().len()
    }

    pub fn remaining_script<'a>(&'a self) -> &'a Script {
        let pos = self.script_position();
        &self.script[pos..]
    }

    pub fn stack(&self) -> &Stack {
        &self.stack
    }

    pub fn altstack(&self) -> &Stack {
        &self.altstack
    }

    pub fn stats(&self) -> &ExecStats {
        &self.stats
    }

    ///////////////
    // UTILITIES //
    ///////////////

    fn fail(&mut self, err: ExecError) -> Result<(), &ExecutionResult> {
        let res = ExecutionResult {
            success: false,
            error: Some(err),
            opcode: None,
            final_stack: self.stack.clone(),
        };
        self.result = Some(res);
        Err(self.result.as_ref().unwrap())
    }

    fn failop(&mut self, err: ExecError, op: Opcode) -> Result<(), &ExecutionResult> {
        let res = ExecutionResult {
            success: false,
            error: Some(err),
            opcode: Some(op),
            final_stack: self.stack.clone(),
        };
        self.result = Some(res);
        Err(self.result.as_ref().unwrap())
    }

    fn check_lock_time(&mut self, lock_time: i64) -> bool {
        use bitcoin::locktime::absolute::LockTime;
        let lock_time = match lock_time.try_into() {
            Ok(l) => LockTime::from_consensus(l),
            Err(_) => return false,
        };

        match (lock_time, self.tx.tx.lock_time) {
            (LockTime::Blocks(h1), LockTime::Blocks(h2)) if h1 > h2 => return false,
            (LockTime::Seconds(t1), LockTime::Seconds(t2)) if t1 > t2 => return false,
            (LockTime::Blocks(_), LockTime::Seconds(_)) => return false,
            (LockTime::Seconds(_), LockTime::Blocks(_)) => return false,
            _ => {}
        }

        if self.tx.tx.input[self.tx.input_idx].sequence.is_final() {
            return false;
        }

        true
    }

    fn check_sequence(&mut self, sequence: i64) -> bool {
        use bitcoin::locktime::relative::LockTime;

        // Fail if the transaction's version number is not set high
        // enough to trigger BIP 68 rules.
        if self.tx.tx.version < transaction::Version::TWO {
            return false;
        }

        let input_sequence = self.tx.tx.input[self.tx.input_idx].sequence;
        let input_lock_time = match input_sequence.to_relative_lock_time() {
            Some(lt) => lt,
            None => return false,
        };

        let lock_time = match LockTime::from_num(sequence) {
            Some(lt) => lt,
            None => return false,
        };

        match (lock_time, input_lock_time) {
            (LockTime::Blocks(h1), LockTime::Blocks(h2)) if h1 > h2 => return false,
            (LockTime::Time(t1), LockTime::Time(t2)) if t1 > t2 => return false,
            (LockTime::Blocks(_), LockTime::Time(_)) => return false,
            (LockTime::Time(_), LockTime::Blocks(_)) => return false,
            _ => {}
        }

        true
    }

    fn check_sig_pre_tap(&mut self, sig: &[u8], pk: &[u8]) -> Result<bool, ExecError> {
        //TODO(stevenroose) somehow sigops limit should be checked somewhere

        // Drop the signature in pre-segwit scripts but not segwit scripts
        let mut scriptcode = Cow::Borrowed(self.script_code.as_bytes());
        if self.ctx == ExecCtx::Legacy {
            let mut i = 0;
            while i < scriptcode.len() - sig.len() {
                if &scriptcode[i..i + sig.len()] == sig {
                    scriptcode.to_mut().drain(i..i + sig.len());
                } else {
                    i += 1;
                }
            }
        }

        //TODO(stevenroose) the signature and pk encoding checks we use here
        // might not be exactly identical to Core's

        if self.ctx == ExecCtx::SegwitV0 && pk.len() == 65 {
            return Err(ExecError::WitnessPubkeyType);
        }

        Ok(self.check_sig_ecdsa(sig, pk, &scriptcode))
    }

    fn check_sig_tap(&mut self, sig: &[u8], pk: &[u8]) -> Result<bool, ExecError> {
        if !sig.is_empty() {
            self.validation_weight -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
            if self.validation_weight < 0 {
                return Err(ExecError::TapscriptValidationWeight);
            }
        }

        if pk.is_empty() {
            Err(ExecError::PubkeyType)
        } else if pk.len() == 32 {
            if !sig.is_empty() {
                self.check_sig_schnorr(sig, pk)?;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(true)
        }
    }

    fn check_sig(&mut self, sig: &[u8], pk: &[u8]) -> Result<bool, ExecError> {
        match self.ctx {
            ExecCtx::Legacy | ExecCtx::SegwitV0 => self.check_sig_pre_tap(sig, pk),
            ExecCtx::Tapscript => self.check_sig_tap(sig, pk),
        }
    }

    ///////////////
    // EXECUTION //
    ///////////////

    /// Returns true when execution is done.
    pub fn exec_next(&mut self) -> Result<(), &ExecutionResult> {
        if let Some(ref res) = self.result {
            return Err(res);
        }

        self.current_position = self.script.len() - self.instructions.as_script().len();
        let instruction = match self.instructions.next() {
            Some(Ok(i)) => i,
            None => {
                let res = ExecutionResult::from_final_stack(self.ctx, self.stack.clone());
                self.result = Some(res);
                return Err(self.result.as_ref().unwrap());
            }
            Some(Err(_)) => unreachable!("we checked the script beforehand"),
        };

        let exec = self.cond_stack.all_true();
        match instruction {
            Instruction::PushBytes(p) => {
                if p.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return self.fail(ExecError::PushSize);
                }
                if exec {
                    self.stack.pushstr(p.as_bytes());
                }
            }
            Instruction::Op(op) => {
                // Some things we do even when we're not executing.

                // Note how OP_RESERVED does not count towards the opcode limit.
                if self.ctx == ExecCtx::Legacy || self.ctx == ExecCtx::SegwitV0 {
                    if op.to_u8() > OP_PUSHNUM_16.to_u8() {
                        self.opcode_count += 1;
                        if self.opcode_count > MAX_OPS_PER_SCRIPT {
                            return self.fail(ExecError::OpCount);
                        }
                    }
                }

                match op {
                    OP_CAT if !self.opt.experimental.op_cat || self.ctx != ExecCtx::Tapscript => {
                        return self.failop(ExecError::DisabledOpcode, op);
                    }
                    OP_SUBSTR | OP_LEFT | OP_RIGHT | OP_INVERT | OP_AND | OP_OR | OP_XOR
                    | OP_2MUL | OP_2DIV | OP_MUL | OP_DIV | OP_MOD | OP_LSHIFT | OP_RSHIFT => {
                        return self.failop(ExecError::DisabledOpcode, op);
                    }
                    OP_RESERVED => {
                        return self.failop(ExecError::Debug, op);
                    }

                    _ => {}
                }

                if exec || (op.to_u8() >= OP_IF.to_u8() && op.to_u8() <= OP_ENDIF.to_u8()) {
                    if let Err(err) = self.exec_opcode(op) {
                        return self.failop(err, op);
                    }
                }
            }
        }

        self.update_stats();
        Ok(())
    }

    fn exec_opcode(&mut self, op: Opcode) -> Result<(), ExecError> {
        let exec = self.cond_stack.all_true();

        // Remember to leave stack intact until all errors have occurred.
        match op {
            //
            // Push value
            OP_PUSHNUM_NEG1 | OP_PUSHNUM_1 | OP_PUSHNUM_2 | OP_PUSHNUM_3 | OP_PUSHNUM_4
            | OP_PUSHNUM_5 | OP_PUSHNUM_6 | OP_PUSHNUM_7 | OP_PUSHNUM_8 | OP_PUSHNUM_9
            | OP_PUSHNUM_10 | OP_PUSHNUM_11 | OP_PUSHNUM_12 | OP_PUSHNUM_13 | OP_PUSHNUM_14
            | OP_PUSHNUM_15 | OP_PUSHNUM_16 => {
                let n = op.to_u8() - (OP_PUSHNUM_1.to_u8() - 2);
                self.stack.pushnum((n as i64) - 1);
            }

            //
            // Control
            OP_NOP => {}

            OP_CLTV if self.opt.verify_cltv => {
                let top = self.stack.topstr(-1)?;

                // Note that elsewhere numeric opcodes are limited to
                // operands in the range -2**31+1 to 2**31-1, however it is
                // legal for opcodes to produce results exceeding that
                // range. This limitation is implemented by CScriptNum's
                // default 4-byte limit.
                //
                // If we kept to that limit we'd have a year 2038 problem,
                // even though the nLockTime field in transactions
                // themselves is uint32 which only becomes meaningless
                // after the year 2106.
                //
                // Thus as a special case we tell CScriptNum to accept up
                // to 5-byte bignums, which are good until 2**39-1, well
                // beyond the 2**32-1 limit of the nLockTime field itself.
                let n = read_scriptint(&top, 5, self.opt.require_minimal)?;

                if n < 0 {
                    return Err(ExecError::NegativeLocktime);
                }

                if !self.check_lock_time(n) {
                    return Err(ExecError::UnsatisfiedLocktime);
                }
            }
            OP_CLTV => {} // otherwise nop

            OP_CSV if self.opt.verify_csv => {
                let top = self.stack.topstr(-1)?;

                // nSequence, like nLockTime, is a 32-bit unsigned integer
                // field. See the comment in CHECKLOCKTIMEVERIFY regarding
                // 5-byte numeric operands.
                let n = read_scriptint(&top, 5, self.opt.require_minimal)?;

                if n < 0 {
                    return Err(ExecError::NegativeLocktime);
                }

                //TODO(stevenroose) check this logic
                //TODO(stevenroose) check if this cast is ok
                if n & SEQUENCE_LOCKTIME_DISABLE_FLAG as i64 == 0 {
                    if !self.check_sequence(n) {
                        return Err(ExecError::UnsatisfiedLocktime);
                    }
                }
            }
            OP_CSV => {} // otherwise nop

            OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {
                // nops
            }

            OP_IF | OP_NOTIF => {
                if exec {
                    let top = self.stack.topstr(-1)?;

                    // Tapscript requires minimal IF/NOTIF inputs as a consensus rule.
                    if self.ctx == ExecCtx::Tapscript {
                        // The input argument to the OP_IF and OP_NOTIF opcodes must be either
                        // exactly 0 (the empty vector) or exactly 1 (the one-byte vector with value 1).
                        if top.len() > 1 || (top.len() == 1 && top[0] != 1) {
                            return Err(ExecError::TapscriptMinimalIf);
                        }
                    }
                    // Under segwit v0 only enabled as policy.
                    if self.opt.verify_minimal_if && self.ctx == ExecCtx::SegwitV0 {
                        if top.len() > 1 || (top.len() == 1 && top[0] != 1) {
                            return Err(ExecError::TapscriptMinimalIf);
                        }
                    }
                    let b = if op == OP_NOTIF {
                        !script::read_scriptbool(&top)
                    } else {
                        script::read_scriptbool(&top)
                    };
                    self.stack.pop().unwrap();
                    self.cond_stack.push(b);
                } else {
                    self.cond_stack.push(false);
                }
            }

            OP_ELSE => {
                if !self.cond_stack.toggle_top() {
                    return Err(ExecError::UnbalancedConditional);
                }
            }

            OP_ENDIF => {
                if !self.cond_stack.pop() {
                    return Err(ExecError::UnbalancedConditional);
                }
            }

            OP_VERIFY => {
                let top = self.stack.topstr(-1)?;

                if !script::read_scriptbool(&top) {
                    return Err(ExecError::Verify);
                } else {
                    self.stack.pop().unwrap();
                }
            }

            OP_RETURN => return Err(ExecError::OpReturn),

            //
            // Stack operations
            OP_TOALTSTACK => {
                let top = self.stack.pop().ok_or(ExecError::InvalidStackOperation)?;
                self.altstack.push(top);
            }

            OP_FROMALTSTACK => {
                let top = self
                    .altstack
                    .pop()
                    .ok_or(ExecError::InvalidStackOperation)?;
                self.stack.push(top);
            }

            OP_2DROP => {
                // (x1 x2 -- )
                self.stack.needn(2)?;
                self.stack.popn(2).unwrap();
            }

            OP_2DUP => {
                // (x1 x2 -- x1 x2 x1 x2)
                let x1 = self.stack.top(-2)?.clone();
                let x2 = self.stack.top(-1)?.clone();
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_3DUP => {
                // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                let x1 = self.stack.top(-3)?.clone();
                let x2 = self.stack.top(-2)?.clone();
                let x3 = self.stack.top(-1)?.clone();
                self.stack.push(x1);
                self.stack.push(x2);
                self.stack.push(x3);
            }

            OP_2OVER => {
                // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                self.stack.needn(4)?;
                let x1 = self.stack.top(-4)?.clone();
                let x2 = self.stack.top(-3)?.clone();
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_2ROT => {
                // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                self.stack.needn(6)?;
                let x6 = self.stack.pop().unwrap();
                let x5 = self.stack.pop().unwrap();
                let x4 = self.stack.pop().unwrap();
                let x3 = self.stack.pop().unwrap();
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push(x3);
                self.stack.push(x4);
                self.stack.push(x5);
                self.stack.push(x6);
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_2SWAP => {
                // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                self.stack.needn(4)?;
                let x4 = self.stack.pop().unwrap();
                let x3 = self.stack.pop().unwrap();
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push(x3);
                self.stack.push(x4);
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_IFDUP => {
                // (x - 0 | x x)
                let top = self.stack.topstr(-1)?;
                if script::read_scriptbool(&top) {
                    self.stack.push(self.stack.top(-1)?.clone());
                }
            }

            OP_DEPTH => {
                // -- stacksize
                self.stack.pushnum(self.stack.len() as i64);
            }

            OP_DROP => {
                // (x -- )
                if self.stack.pop().is_none() {
                    return Err(ExecError::InvalidStackOperation);
                }
            }

            OP_DUP => {
                // (x -- x x)
                let top = self.stack.top(-1)?.clone();
                self.stack.push(top);
            }

            OP_NIP => {
                // (x1 x2 -- x2)
                self.stack.needn(2)?;
                let x2 = self.stack.pop().unwrap();
                self.stack.pop().unwrap();
                self.stack.push(x2);
            }

            OP_OVER => {
                // (x1 x2 -- x1 x2 x1)
                let under_top = self.stack.top(-2)?.clone();
                self.stack.push(under_top);
            }

            OP_PICK | OP_ROLL => {
                // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                let x = self.stack.topnum(-1, self.opt.require_minimal)?;
                if x < 0 || x >= self.stack.len() as i64 {
                    return Err(ExecError::InvalidStackOperation);
                }
                self.stack.pop().unwrap();
                let elem = self.stack.top(-x as isize - 1).unwrap().clone();
                if op == OP_ROLL {
                    self.stack.remove(self.stack.len() - x as usize - 1);
                }
                self.stack.push(elem);
            }

            OP_ROT => {
                // (x1 x2 x3 -- x2 x3 x1)
                self.stack.needn(3)?;
                let x3 = self.stack.pop().unwrap();
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push(x2);
                self.stack.push(x3);
                self.stack.push(x1);
            }

            OP_SWAP => {
                // (x1 x2 -- x2 x1)
                self.stack.needn(2)?;
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push(x2);
                self.stack.push(x1);
            }

            OP_TUCK => {
                // (x1 x2 -- x2 x1 x2)
                self.stack.needn(2)?;
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push(x2.clone());
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_CAT if self.opt.experimental.op_cat && self.ctx == ExecCtx::Tapscript => {
                // (x1 x2 -- x1|x2)
                self.stack.needn(2)?;
                let x2 = self.stack.popstr().unwrap();
                let x1 = self.stack.popstr().unwrap();
                let ret: Vec<u8> = x1.into_iter().chain(x2.into_iter()).collect();
                if ret.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(ExecError::PushSize);
                }
                self.stack.pushstr(&ret);
            }

            OP_SIZE => {
                // (in -- in size)
                let top = self.stack.topstr(-1)?;
                self.stack.pushnum(top.len() as i64);
            }

            //
            // Bitwise logic
            OP_EQUAL | OP_EQUALVERIFY => {
                // (x1 x2 - bool)
                self.stack.needn(2)?;
                let x2 = self.stack.popstr().unwrap();
                let x1 = self.stack.popstr().unwrap();
                let equal = x1 == x2;
                if op == OP_EQUALVERIFY && !equal {
                    return Err(ExecError::EqualVerify);
                }
                if op == OP_EQUAL {
                    let item = if equal { 1 } else { 0 };
                    self.stack.pushnum(item);
                }
            }

            //
            // Numeric
            OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                // (in -- out)
                let x = self.stack.topnum(-1, self.opt.require_minimal)?;
                let res = match op {
                    OP_1ADD => x
                        .checked_add(1)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_1SUB => x
                        .checked_sub(1)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_NEGATE => x.checked_neg().ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_ABS => x.abs(),
                    OP_NOT => (x == 0) as i64,
                    OP_0NOTEQUAL => (x != 0) as i64,
                    _ => unreachable!(),
                };
                self.stack.pop().unwrap();
                self.stack.pushnum(res);
            }

            OP_ADD
            | OP_SUB
            | OP_BOOLAND
            | OP_BOOLOR
            | OP_NUMEQUAL
            | OP_NUMEQUALVERIFY
            | OP_NUMNOTEQUAL
            | OP_LESSTHAN
            | OP_GREATERTHAN
            | OP_LESSTHANOREQUAL
            | OP_GREATERTHANOREQUAL
            | OP_MIN
            | OP_MAX => {
                // (x1 x2 -- out)
                let x1 = self.stack.topnum(-2, self.opt.require_minimal)?;
                let x2 = self.stack.topnum(-1, self.opt.require_minimal)?;
                let res = match op {
                    OP_ADD => x1
                        .checked_add(x2)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_SUB => x1
                        .checked_sub(x2)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_BOOLAND => (x1 != 0 && x2 != 0) as i64,
                    OP_BOOLOR => (x1 != 0 || x2 != 0) as i64,
                    OP_NUMEQUAL => (x1 == x2) as i64,
                    OP_NUMEQUALVERIFY => (x1 == x2) as i64,
                    OP_NUMNOTEQUAL => (x1 != x2) as i64,
                    OP_LESSTHAN => (x1 < x2) as i64,
                    OP_GREATERTHAN => (x1 > x2) as i64,
                    OP_LESSTHANOREQUAL => (x1 <= x2) as i64,
                    OP_GREATERTHANOREQUAL => (x1 >= x2) as i64,
                    OP_MIN => cmp::min(x1, x2),
                    OP_MAX => cmp::max(x1, x2),
                    _ => unreachable!(),
                };
                if op == OP_NUMEQUALVERIFY && res == 0 {
                    return Err(ExecError::NumEqualVerify);
                }
                self.stack.popn(2).unwrap();
                if op != OP_NUMEQUALVERIFY {
                    self.stack.pushnum(res);
                }
            }

            OP_WITHIN => {
                // (x min max -- out)
                let x1 = self.stack.topnum(-3, self.opt.require_minimal)?;
                let x2 = self.stack.topnum(-2, self.opt.require_minimal)?;
                let x3 = self.stack.topnum(-1, self.opt.require_minimal)?;
                self.stack.popn(3).unwrap();
                let res = x2 <= x1 && x1 < x3;
                let item = if res { 1 } else { 0 };
                self.stack.pushnum(item);
            }

            //
            // Crypto

            // (in -- hash)
            OP_RIPEMD160 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(&ripemd160::Hash::hash(&top[..]).to_byte_array().to_vec());
            }
            OP_SHA1 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(&sha1::Hash::hash(&top[..]).to_byte_array().to_vec());
            }
            OP_SHA256 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(&sha256::Hash::hash(&top[..]).to_byte_array().to_vec());
            }
            OP_HASH160 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(&hash160::Hash::hash(&top[..]).to_byte_array().to_vec());
            }
            OP_HASH256 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(&sha256d::Hash::hash(&top[..]).to_byte_array().to_vec());
            }

            OP_CODESEPARATOR => {
                // Store this CODESEPARATOR position and update the scriptcode.
                self.last_codeseparator_pos = Some(self.current_position as u32);
                self.script_code = &self.script[self.current_position..];
            }

            OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                let sig = self.stack.topstr(-2)?.clone();
                let pk = self.stack.topstr(-1)?.clone();
                let res = self.check_sig(&sig, &pk)?;
                self.stack.popn(2).unwrap();
                if op == OP_CHECKSIGVERIFY && !res {
                    return Err(ExecError::CheckSigVerify);
                }
                if op == OP_CHECKSIG {
                    let ret = if res { 1 } else { 0 };
                    self.stack.pushnum(ret);
                }
            }

            OP_CHECKSIGADD => {
                if self.ctx == ExecCtx::Legacy || self.ctx == ExecCtx::SegwitV0 {
                    return Err(ExecError::BadOpcode);
                }
                let sig = self.stack.topstr(-3)?.clone();
                let mut n = self.stack.topnum(-2, self.opt.require_minimal)?;
                let pk = self.stack.topstr(-1)?.clone();
                let res = self.check_sig(&sig, &pk)?;
                self.stack.popn(3).unwrap();
                if res {
                    n += 1;
                }
                self.stack.pushnum(n);
            }

            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                unimplemented!();
            }

            // remainder
            _ => return Err(ExecError::BadOpcode),
        }

        if self.stack.len() + self.altstack.len() > MAX_STACK_SIZE {
            return Err(ExecError::StackSize);
        }

        Ok(())
    }

    ////////////////
    // STATISTICS //
    ////////////////

    fn update_stats(&mut self) {
        let stack_items = self.stack.len() + self.altstack.len();
        self.stats.max_nb_stack_items = cmp::max(self.stats.max_nb_stack_items, stack_items);

        self.stats.opcode_count = self.opcode_count;
        self.stats.validation_weight = self.validation_weight;
    }
}

fn read_scriptint(item: &[u8], size: usize, minimal: bool) -> Result<i64, ExecError> {
    script::read_scriptint_size(item, size, minimal).map_err(|e| match e {
        script::ScriptIntError::NonMinimalPush => ExecError::MinimalData,
        // only possible if size is 4 or lower
        script::ScriptIntError::NumericOverflow => ExecError::ScriptIntNumericOverflow,
    })
}
