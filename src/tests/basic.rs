use bitcoin::{hashes::Hash, hex::DisplayHex, ScriptBuf, TapLeafHash, Transaction};

use super::helpers::FromAsm;
use crate::{Exec, TxTemplate};

#[test]
fn basic() {
    let script_asm = "OP_IF OP_2 OP_ELSE OP_4 OP_4 OP_CAT OP_ENDIF";

    let script = ScriptBuf::from_asm(script_asm).expect("error parsing script");
    println!("Script in hex: {}", script.as_bytes().to_lower_hex_string());
    println!("Script size: {} bytes", script.as_bytes().len());

    let mut exec = Exec::new(
        TxTemplate {
            tx: Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            prevouts: vec![],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        },
        script,
        vec![vec![]],
    )
    .expect("error creating exec");

    loop {
        println!(
            "Remaining script: [{}]",
            exec.remaining_script().to_asm_string()
        );
        println!("Stack: [{}]", exec.stack());
        println!("AltStack: [{}]", exec.altstack());
        println!("--------------------------------------------------");

        let next = exec.exec_next();
        if next.is_err() {
            println!("Error {next:?}");
            break;
        }
    }

    let result = exec.result().unwrap();

    println!("Result [{}]", result.final_stack);

    assert!(result.success);
    assert_eq!(result.final_stack.to_string(), "1028");
}
