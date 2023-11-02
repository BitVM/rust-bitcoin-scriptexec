
use std::{cmp, io};

use bitcoin::consensus::Encodable;
use bitcoin::hashes::{Hash, ripemd160, sha1, sha256, hash160, sha256d};
use bitcoin::opcodes::{self, all::*, Opcode};
use bitcoin::script::{self, Instruction, Instructions, Script};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::{self, Transaction, TxOut};

#[cfg(feature = "serde")]
use serde;

#[macro_use]
mod macros;

mod signatures;

mod error;
pub use error::{Error, ExecError};

#[cfg(feature = "wasm")]
mod wasm;


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
const MAX_PUBKEYS_PER_MULTISIG: i64 = 20;


/// The stack item representing true.
fn item_true() -> Vec<u8> {
	vec![1]
}
/// The stack item representing false.
fn item_false() -> Vec<u8> {
	vec![]
}

pub struct Options {
	/// Require data pushes be minimally encoded.
	pub require_minimal: bool, //TODO(stevenroose) double check all fRequireMinimal usage in Core
	/// Verify OP_CHECKLOCKTIMEVERIFY.
	pub verify_cltv: bool,
	/// Verify OP_CHECKSEQUENCEVERIFY.
	pub verify_csv: bool,
	/// Verify conditionals are minimally encoded.
	pub verify_minimal_if: bool,
	/// Making OP_CODESEPARATOR and FindAndDelete fail any non-segwit scripts
	pub verify_const_scriptcode: bool,
}

impl Default for Options {
	fn default() -> Self {
		Options {
			require_minimal: true,
			verify_cltv: true,
			verify_csv: true,
			verify_minimal_if: true,
			verify_const_scriptcode: true,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
	pub success: bool,
	pub error: Option<ExecError>,
	pub opcode: Option<Opcode>,
	pub final_stack: Vec<Vec<u8>>,
}

impl ExecutionResult {
	fn from_final_stack(final_stack: Vec<Vec<u8>>) -> ExecutionResult {
		ExecutionResult {
			success: final_stack == vec![vec![opcodes::OP_TRUE.to_u8()]],
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
	pub max_nb_stack_items: usize,
	/// The highest total stack size occurred during execution.
	pub max_stack_size: usize,

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
	cond_stack: Vec<bool>,
	stack: Vec<Vec<u8>>,
	altstack: Vec<Vec<u8>>,
	last_codeseparator_pos: Option<usize>,
	// Initially set to the whole script, but updated when
	// OP_CODESEPARATOR is encountered.
	script_code: &'static Script,

	opcode_count: usize, //TODO(stevenroose) once correctly implemented, add to stats
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
		script: &Script,
		script_witness: Vec<Vec<u8>>,
	) -> Result<Exec, Error> {
		// We box alocate the script to get a static Instructions iterator.
		// We will manually drop this allocation in the ops::Drop impl.
		let script = Box::leak(script.to_owned().into_boxed_script()) as &'static Script;
		let instructions = if opt.require_minimal {
			script.instructions_minimal()
		} else {
			script.instructions()
		};

		// We want to make sure the script is valid so we don't have to throw parsing errors
		// while executing.
		if let Some(err) = instructions.clone().find_map(|res| res.err()) {
			return Err(Error::InvalidScript(err));
		}

		//TODO(stevenroose) make this more efficient
		let witness_size = Encodable::consensus_encode(&script_witness, &mut io::sink()).unwrap();
		let start_validation_weight = VALIDATION_WEIGHT_OFFSET + witness_size as i64;

		let mut ret = Exec {
			ctx: ctx,
			result: None,

			//TODO(stevenroose) think about miminal
			sighashcache: SighashCache::new(tx.tx.clone()),
			script: script,
			instructions: instructions,
			current_position: 0,
			cond_stack: Vec::new(),
			//TODO(stevenroose) does this need to be reversed?
			stack: script_witness.clone(),
			altstack: Vec::new(),
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

	pub fn stats(&self) -> &ExecStats {
		&self.stats
	}

	fn fail(&mut self, err: ExecError) -> Result<(), ExecutionResult> {
		let res = ExecutionResult {
			success: false,
			error: Some(err),
			opcode: None,
			final_stack: self.stack.clone(),
		};
		self.result = Some(res.clone());
		Err(res)
	}

	fn failop(&mut self, err: ExecError, op: Opcode) -> Result<(), ExecutionResult> {
		let res = ExecutionResult {
			success: false,
			error: Some(err),
			opcode: Some(op),
			final_stack: self.stack.clone(),
		};
		self.result = Some(res.clone());
		Err(res)
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
			_ => {},
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
			_ => {},
		}

		true
	}

	fn check_sig_pre_tap(&mut self, sig: &[u8], pk: &[u8]) -> Result<bool, ExecError> {
		unimplemented!();
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
			}
			Ok(true)
		} else {
			/*
			 *  New public key version softforks should be defined before this `else` block.
			 *  Generally, the new code should not do anything but failing the script execution. To avoid
			 *  consensus bugs, it should not modify any existing values (including `success`).
			 */
			// if ((flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE) != 0) {
			// 	return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE);
			// }
			//TODO(stevenroose) something with discourage stuff
			Ok(true)
		}
	}

	fn check_sig(&mut self, sig: &[u8], pk: &[u8]) -> Result<bool, ExecError> {
		match self.ctx {
			ExecCtx::Legacy | ExecCtx::SegwitV0 => self.check_sig_pre_tap(sig, pk),
			ExecCtx::Tapscript => self.check_sig_tap(sig, pk),
		}
	}

	/// Get items from the top of the stack.
	///
	/// F.e. with [offset] equal to -1, this returns the last element.
	fn stacktop(&self, offset: isize) -> Result<&Vec<u8>, ExecError> {
		debug_assert!(offset < 0, "offsets should be < 0");
		self.stack.len().checked_sub(offset.abs() as usize).and_then(|i| {
			self.stack.iter().nth(i)
		}).ok_or(ExecError::InvalidStackOperation)
	}

	/// Returns true when execution is done.
	pub fn exec_next(&mut self) -> Result<(), ExecutionResult> {
		if let Some(ref res) = self.result {
			return Err(res.clone());
		}

		self.current_position = self.script.len() - self.instructions.as_script().len();
		let instruction = match self.instructions.next() {
			Some(Ok(i)) => i,
			None => {
				let res = ExecutionResult::from_final_stack(self.stack.clone());
				self.result = Some(res.clone());
				return Err(res)
			}
			Some(Err(_)) => unreachable!("we checked the script beforehand"),
		};

		let exec = self.cond_stack.iter().all(|v| *v);
		match instruction {
			Instruction::PushBytes(p) => {
				if p.len() > MAX_SCRIPT_ELEMENT_SIZE {
					return self.fail(ExecError::PushSize)
				}
				if exec {
					self.stack.push(p.as_bytes().to_vec());
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
					OP_CAT | OP_SUBSTR | OP_LEFT | OP_RIGHT | OP_INVERT | OP_AND | OP_OR | OP_XOR | OP_2MUL
						| OP_2DIV | OP_MUL | OP_DIV | OP_MOD | OP_LSHIFT | OP_RSHIFT =>
					{
						return self.failop(ExecError::DisabledOpcode, op);
					}

					OP_CODESEPARATOR if self.opt.verify_const_scriptcode => {
						return self.fail(ExecError::OpCodeseparator);
					}

					_ => {},
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
		let exec = self.cond_stack.iter().all(|v| *v);

		// Remember to leave stack intact until all errors have occurred.
		match op {
			//
			// Push value

			OP_PUSHNUM_NEG1 | OP_PUSHNUM_1 | OP_PUSHNUM_2 | OP_PUSHNUM_3 | OP_PUSHNUM_4 |
			OP_PUSHNUM_5 | OP_PUSHNUM_6 | OP_PUSHNUM_7 | OP_PUSHNUM_8 | OP_PUSHNUM_9 |
			OP_PUSHNUM_10 | OP_PUSHNUM_11 | OP_PUSHNUM_12 | OP_PUSHNUM_13 | OP_PUSHNUM_14 | 
			OP_PUSHNUM_15 | OP_PUSHNUM_16 =>
			{
				let n = op.to_u8() - (OP_PUSHNUM_1.to_u8() - 1);
				self.stack.push(script::scriptint_vec(n as i64));
			}

			//
			// Control

			OP_NOP => {},

			OP_CLTV if self.opt.verify_cltv => {
				let top = self.stacktop(-1)?;

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
				let n = read_scriptint(top, 5, self.opt.require_minimal)?;

				if n < 0 {
					return Err(ExecError::NegativeLocktime);
				}

				if !self.check_lock_time(n) {
					return Err(ExecError::UnsatisfiedLocktime);
				}
			}
			OP_CLTV => {}, // otherwise nop

			OP_CSV if self.opt.verify_csv => {
				let top = self.stacktop(-1)?;

				// nSequence, like nLockTime, is a 32-bit unsigned integer
				// field. See the comment in CHECKLOCKTIMEVERIFY regarding
				// 5-byte numeric operands.
				let n = read_scriptint(top, 5, self.opt.require_minimal)?;

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
			OP_CSV => {}, // otherwise nop

			OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {
				//TODO(stevenroose) discourage upgradable nops?
			}

			OP_IF | OP_NOTIF => {
				if exec {
					let top = self.stacktop(-1)?;

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
						!script::read_scriptbool(top)
					} else {
						script::read_scriptbool(top)
					};
					self.stack.pop();
					self.cond_stack.push(b);
				} else {
					self.cond_stack.push(false);
				}
			}

			OP_ELSE => {
				if let Some(top) = self.cond_stack.last_mut() {
					*top = !*top;
				} else {
					return Err(ExecError::UnbalancedConditional);
				}
			}

			OP_ENDIF => {
				if self.cond_stack.pop().is_none() {
					return Err(ExecError::UnbalancedConditional);
				}
			}

			OP_VERIF => {
				let top = self.stacktop(-1)?;

				if !script::read_scriptbool(top) {
					return Err(ExecError::Verify);
				} else {
					self.stack.pop();
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
				let top = self.altstack.pop().ok_or(ExecError::InvalidStackOperation)?;
				self.stack.push(top);
			}

			OP_2DROP => {
				// (x1 x2 -- )
				if self.stack.len() < 2 {
					return Err(ExecError::InvalidStackOperation);
				}
				self.stack.pop();
				self.stack.pop();
			}

			OP_2DUP => {
				// (x1 x2 -- x1 x2 x1 x2)
				if self.stack.len() < 2 {
					return Err(ExecError::InvalidStackOperation);
				}
				let x1 = self.stacktop(-2).unwrap().clone();
				let x2 = self.stacktop(-1).unwrap().clone();
				self.stack.push(x1);
				self.stack.push(x2);
			}

			OP_3DUP => {
				// (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
				if self.stack.len() < 3 {
					return Err(ExecError::InvalidStackOperation);
				}
				let x1 = self.stacktop(-3).unwrap().clone();
				let x2 = self.stacktop(-2).unwrap().clone();
				let x3 = self.stacktop(-1).unwrap().clone();
				self.stack.push(x1);
				self.stack.push(x2);
				self.stack.push(x3);
			}

			OP_2OVER => {
				// (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
				if self.stack.len() < 4 {
					return Err(ExecError::InvalidStackOperation);
				}
				let x1 = self.stacktop(-4).unwrap().clone();
				let x2 = self.stacktop(-3).unwrap().clone();
				self.stack.push(x1);
				self.stack.push(x2);
			}

			OP_2ROT => {
				// (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
				if self.stack.len() < 6 {
					return Err(ExecError::InvalidStackOperation);
				}
				let x6 = self.stack.pop().unwrap();
				let x5 = self.stack.pop().unwrap();
				let x4 = self.stack.pop().unwrap();
				let x3 = self.stack.pop().unwrap();
				let x2 = self.stack.pop().unwrap();
				let x1 = self.stack.pop().unwrap();
				self.stack.push(x3.clone());
				self.stack.push(x4.clone());
				self.stack.push(x5.clone());
				self.stack.push(x6.clone());
				self.stack.push(x1.clone());
				self.stack.push(x2.clone());
			}

			OP_2SWAP => {
				// (x1 x2 x3 x4 -- x3 x4 x1 x2)
				if self.stack.len() < 4 {
					return Err(ExecError::InvalidStackOperation);
				}
				let x4 = self.stack.pop().unwrap();
				let x3 = self.stack.pop().unwrap();
				let x2 = self.stack.pop().unwrap();
				let x1 = self.stack.pop().unwrap();
				self.stack.push(x3.clone());
				self.stack.push(x4.clone());
				self.stack.push(x1.clone());
				self.stack.push(x2.clone());
			}

			OP_IFDUP => {
				// (x - 0 | x x)
				let top = self.stacktop(-1)?;
				if script::read_scriptbool(top) {
					self.stack.push(top.clone());
				}
			}

			OP_DEPTH => {
				// -- stacksize
				self.stack.push(script::scriptint_vec(self.stack.len() as i64));
			}

			OP_DROP => {
				// (x -- )
				if self.stack.pop().is_none() {
					return Err(ExecError::InvalidStackOperation);
				}
			}

			OP_DUP => {
				// (x -- x x)
				let top = self.stacktop(-1)?;
				self.stack.push(top.clone());
			}

			OP_NIP => {
				// (x1 x2 -- x2)
				if self.stack.len() < 2 {
					return Err(ExecError::InvalidStackOperation);
				}
				let x2 = self.stack.pop().unwrap();
				self.stack.pop().unwrap();
				self.stack.push(x2);
			}

			OP_OVER => {
				// (x1 x2 -- x1 x2 x1)
				let under_top = self.stacktop(-2)?;
				self.stack.push(under_top.clone());
			}

			OP_PICK | OP_ROLL => {
				// (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
				// (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
				let top = self.stacktop(-1)?;
				let n = read_scriptint(top, 4, self.opt.require_minimal)?;
				if n < 0 || n >= self.stack.len() as i64 {
					return Err(ExecError::InvalidStackOperation);
				}
				self.stack.pop().unwrap();
				let elem = self.stacktop(- n as isize - 1).unwrap().clone();
				if op == OP_ROLL {
					self.stack.remove(self.stack.len() - n as usize - 1);
				}
				self.stack.push(elem);
			}

			OP_ROT => {
				// (x1 x2 x3 -- x2 x3 x1)
				if self.stack.len() < 3 {
					return Err(ExecError::InvalidStackOperation);
				}
				let x3 = self.stack.pop().unwrap();
				let x2 = self.stack.pop().unwrap();
				let x1 = self.stack.pop().unwrap();
				self.stack.push(x2.clone());
				self.stack.push(x3.clone());
				self.stack.push(x1.clone());
			}

			OP_SWAP => {
				// (x1 x2 -- x2 x1)
				if self.stack.len() < 2 {
					return Err(ExecError::InvalidStackOperation);
				}
				let x2 = self.stack.pop().unwrap();
				let x1 = self.stack.pop().unwrap();
				self.stack.push(x2.clone());
				self.stack.push(x1.clone());
			}

			OP_TUCK => {
				// (x1 x2 -- x2 x1 x2)
				if self.stack.len() < 2 {
					return Err(ExecError::InvalidStackOperation);
				}
				let x2 = self.stack.pop().unwrap();
				let x1 = self.stack.pop().unwrap();
				self.stack.push(x2.clone());
				self.stack.push(x1.clone());
				self.stack.push(x2.clone());
			}

			OP_SIZE => {
				// (in -- in size)
				let top = self.stacktop(-1)?;
				self.stack.push(script::scriptint_vec(top.len() as i64));
			}

			//
			// Bitwise logic

			OP_EQUAL | OP_EQUALVERIFY => {
				// (x1 x2 - bool)
				if self.stack.len() < 2 {
					return Err(ExecError::InvalidStackOperation);
				}
				let x2 = self.stack.pop().unwrap();
				let x1 = self.stack.pop().unwrap();
				let equal = x1 == x2;
				if op == OP_EQUALVERIFY && !equal {
					return Err(ExecError::EqualVerify);
				}
				if op == OP_EQUAL {
					let item = if equal { item_true() } else { item_false() };
					self.stack.push(item);
				}
			}

			//
			// Numeric

			OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
				// (in -- out)
				let top = self.stacktop(-1)?;
				let n = read_scriptint(top, 4, self.opt.require_minimal)?;
				let res = match op {
					OP_1ADD => n.checked_add(1).ok_or(ExecError::ScriptIntNumericOverflow)?,
					OP_1SUB => n.checked_sub(1).ok_or(ExecError::ScriptIntNumericOverflow)?,
					OP_NEGATE => n.checked_neg().ok_or(ExecError::ScriptIntNumericOverflow)?,
					OP_ABS => n.abs(),
					OP_NOT => (n == 0) as i64,
					OP_0NOTEQUAL => (n != 0) as i64,
					_ => unreachable!(),
				};
				self.stack.pop().unwrap();
				self.stack.push(script::scriptint_vec(res));
			}

			OP_ADD | OP_SUB | OP_BOOLAND | OP_BOOLOR | OP_NUMEQUAL | OP_NUMEQUALVERIFY |
			OP_NUMNOTEQUAL | OP_LESSTHAN | OP_GREATERTHAN | OP_LESSTHANOREQUAL |
			OP_GREATERTHANOREQUAL | OP_MIN | OP_MAX => {
				// (x1 x2 -- out)
				let x1 = self.stacktop(-2)?;
				let x2 = self.stacktop(-1)?;
				let n1 = read_scriptint(x1, 4, self.opt.require_minimal)?;
				let n2 = read_scriptint(x2, 4, self.opt.require_minimal)?;
				let res = match op {
					OP_ADD => n1.checked_add(n2).ok_or(ExecError::ScriptIntNumericOverflow)?,
					OP_SUB => n1.checked_sub(n2).ok_or(ExecError::ScriptIntNumericOverflow)?,
					OP_BOOLAND => (n1 != 0 && n2 != 0) as i64,
					OP_BOOLOR => (n1 != 0 || n2 != 0) as i64,
					OP_NUMEQUAL => (n1 == n2) as i64,
					OP_NUMEQUALVERIFY => (n1 == n2) as i64,
					OP_NUMNOTEQUAL => (n1 != n2) as i64,
					OP_LESSTHAN => (n1 < n2) as i64,
					OP_GREATERTHAN => (n1 > n2) as i64,
					OP_LESSTHANOREQUAL => (n1 <= n2) as i64,
					OP_GREATERTHANOREQUAL => (n1 >= n2) as i64,
					OP_MIN => cmp::min(n1, n2),
					OP_MAX => cmp::max(n1, n2),
					_ => unreachable!(),
				};
				if op == OP_NUMEQUALVERIFY && res == 0 {
					return Err(ExecError::NumEqualVerify);
				}
				self.stack.pop().unwrap();
				self.stack.pop().unwrap();
				if op != OP_NUMEQUALVERIFY {
					self.stack.push(script::scriptint_vec(res));
				}
			}

			OP_WITHIN => {
				// (x min max -- out)
				if self.stack.len() < 2 {
					return Err(ExecError::InvalidStackOperation);
				}
				let x1 = self.stack.pop().unwrap();
				let x2 = self.stack.pop().unwrap();
				let x3 = self.stack.pop().unwrap();
				let res = x2 <= x1 && x1 < x3;
				let item = if res { item_true() } else { item_false() };
				self.stack.push(item);
			}

			//
			// Crypto

			// (in -- hash)
			OP_RIPEMD160 => {
				let top = self.stack.pop().ok_or(ExecError::InvalidStackOperation)?;
				self.stack.push(ripemd160::Hash::hash(&top[..]).to_byte_array().to_vec());
			}
			OP_SHA1 => {
				let top = self.stack.pop().ok_or(ExecError::InvalidStackOperation)?;
				self.stack.push(sha1::Hash::hash(&top[..]).to_byte_array().to_vec());
			}
			OP_SHA256 => {
				let top = self.stack.pop().ok_or(ExecError::InvalidStackOperation)?;
				self.stack.push(sha256::Hash::hash(&top[..]).to_byte_array().to_vec());
			}
			OP_HASH160 => {
				let top = self.stack.pop().ok_or(ExecError::InvalidStackOperation)?;
				self.stack.push(hash160::Hash::hash(&top[..]).to_byte_array().to_vec());
			}
			OP_HASH256 => {
				let top = self.stack.pop().ok_or(ExecError::InvalidStackOperation)?;
				self.stack.push(sha256d::Hash::hash(&top[..]).to_byte_array().to_vec());
			}

			OP_CODESEPARATOR => {
				// Store this CODESEPARATOR position and update the scriptcode.
				self.last_codeseparator_pos = Some(self.current_position);
				self.script_code = &self.script[self.current_position..];
			}

			OP_CHECKSIG | OP_CHECKSIGVERIFY => {
				let sig = self.stacktop(-2)?.clone();
				let pk = self.stacktop(-1)?.clone();
				let res = self.check_sig(&sig, &pk)?;
				self.stack.pop().unwrap();
				self.stack.pop().unwrap();
				if op == OP_CHECKSIGVERIFY && !res {
					return Err(ExecError::CheckSigVerify);
				}
				if op == OP_CHECKSIG {
					let ret = if res { item_true() } else { item_false() };
					self.stack.push(ret);
				}
			}

			OP_CHECKSIGADD => {
				if self.ctx == ExecCtx::Legacy || self.ctx == ExecCtx::SegwitV0 {
					return Err(ExecError::BadOpcode);
				}
				let sig = self.stacktop(-3)?.clone();
				let num = self.stacktop(-2)?;
				let mut n = read_scriptint(&num, 4, self.opt.require_minimal)?;
				let pk = self.stacktop(-1)?.clone();
				let res = self.check_sig(&sig, &pk)?;
				self.stack.pop().unwrap();
				self.stack.pop().unwrap();
				self.stack.pop().unwrap();
				if res {
					n += 1;
				}
				self.stack.push(script::scriptint_vec(n));
			}

			OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
				unimplemented!();
			}

			_ => unimplemented!(),

			// remainder
			_ => return Err(ExecError::BadOpcode),
		}

		if self.stack.len() + self.altstack.len() > MAX_STACK_SIZE {
			return Err(ExecError::StackSize);
		}

		Ok(())
	}

	fn update_stats(&mut self) {
		let stack_items = self.stack.len();
		self.stats.max_nb_stack_items = cmp::max(self.stats.max_nb_stack_items, stack_items);

		let stack_size = self.stack.iter().map(|i| i.len()).sum();
		self.stats.max_stack_size = cmp::max(self.stats.max_stack_size, stack_size);

		self.stats.validation_weight = self.validation_weight;
	}
}

fn read_scriptint(item: &[u8], size: usize, minimal: bool) -> Result<i64, ExecError> {
	script::read_scriptint_size(item, size, minimal).map_err(|e| match e {
		script::ScriptIntError::NonMinimalPush => ExecError::MinimalData,
		// only possible if size is 4 or lower
		script::ScriptIntError::NumericOverflow => ExecError::ScriptIntNumericOverflow,
		_ => unreachable!("not possible"),
	})
}
