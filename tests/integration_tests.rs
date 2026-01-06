use bitcoin_scriptexec::*;
use bitcoin::{Amount, Script, ScriptBuf, TapLeafHash, Transaction, TxOut, consensus::{self, encode::deserialize_hex}, taproot::{LeafVersion, TAPROOT_ANNEX_PREFIX}};

#[test]
fn test_tapscript_op_codeseparator() {
    // A test for the opcode separator handling in a tapscript, using the following script:
    
    // OP_PUSH(pubkey)
    // OP_TUCK
    // OP_CHECKSIGVERIFY // checks with sighash(pos=0xffffffff)
    // OP_CODESEPARATOR
    // OP_TUCK
    // OP_CHECKSIGVERIFY // checks with sighash(pos=3)
    // OP_FALSE
    // OP_IF
    //     OP_CODESEPARATOR
    //     OP_NOP
    //     OP_NOP
    //     OP_NOP
    // OP_ENDIF
    // OP_TUCK
    // OP_CHECKSIGVERIFY // checks with sighash(pos=3), i.e. the OP_CODESEPARATOR in the false branch is ignored
    // OP_CODESEPARATOR
    // OP_CHECKSIG // checks with sighash(pos=15), i.e. the pos is still incremented in the unexecuted branch

    let tx: Transaction = deserialize_hex("02000000000101f23f0bf0a49c532a6cb63500c0627705e713d603e39fbbe5bf6422770152bf8c0100000000ffffffff02f0000000000000000451024e730000000000000000046a020b0b0640fed5f9579ccf43c16ffd51b33b089e3a414bfcf1ece5db028128431babdd8c8a37da443c0d0b29bae2145872a80a2ba1b586fb07d08b9f376197b889199620b440469941f463ec6174c6bc26db4aaf186a0b0cf5fd06580dc998b97ecb936f7f76996209447e9da5415edf153f22070aeb20dddb6cfdb3ef32ef0213f867063474408f1a54c2abd4e0196eef814dc920108e26ddbe80e818650738307c17f74af38b660f99f45b5775cdeba6570bdc63d7d82e0ea769793ae9e2a5f49deacc0ed9124018830010bfafbb78326b372e20cea05746d59fba187d1ea2f75346b2305303c42c3cde94650d5d2b37a143632ec8508426ad76077f87e82aa757451757a068da312067e638cfc6c00b099908f230f676b66722c1b6df06d080ccdc130d4502b603cb7dadab7dad0063ab616161687dadabac21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac000000000").unwrap();
    let prevouts = vec![TxOut {
        value: Amount::from_sat(1000),
        script_pubkey: deserialize_hex("225120cb2c1129b05a4d1621f63d0e98958c34c00958528556dc8aeb8122ddea7f8656").unwrap(),
    }];

    assert!(exec_taproot_input(&tx, 0, &prevouts).success);
}

pub fn exec_taproot_input(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> ExecutionResult {
    let script = tx.input[input_index].witness.tapscript().unwrap();
    let stack = {
        let witness_items = tx.input[input_index].witness.to_vec();
        let last = witness_items.last().unwrap();

        // From BIP341:
        // If there are at least two witness elements, and the first byte of
        // the last element is 0x50, this last element is called annex a
        // and is removed from the witness stack.
        let script_index =
            if witness_items.len() >= 3 && last.first() == Some(&TAPROOT_ANNEX_PREFIX) {
                witness_items.len() - 3
            } else {
                witness_items.len() - 2
            };

        witness_items[0..script_index].to_vec()
    };

    let leaf_hash = TapLeafHash::from_script(
        Script::from_bytes(script.as_bytes()),
        LeafVersion::TapScript,
    );

    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Options::default(),
        TxTemplate {
            tx: tx.clone(),
            prevouts: prevouts.into(),
            input_idx: input_index,
            taproot_annex_scriptleaf: Some((leaf_hash, None)),
        },
        ScriptBuf::from_bytes(script.to_bytes()),
        stack,
    )
    .expect("error creating exec");

    loop {
        if let Err(e) = exec.exec_next() {
            return e.clone();
        }
    }
}