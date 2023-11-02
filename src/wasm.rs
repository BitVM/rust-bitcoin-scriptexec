

use bitcoin::{ScriptBuf, Transaction};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::taproot::{TapLeafHash};
use serde_json::json;
use wasm_bindgen::prelude::*;

use crate::*;

/// Compile ASM into script hex.
#[wasm_bindgen]
pub fn script_asm_to_hex(script_asm: &str) -> Result<String, JsValue> {
	let script = ScriptBuf::parse_asm(script_asm)
		.map_err(|e| format!("error parsing script: {:?}", e))?;
	Ok(script.as_bytes().as_hex().to_string())
}

/// Decode compiled script hex into ASM.
#[wasm_bindgen]
pub fn script_hex_to_asm(script_hex: &str) -> Result<String, JsValue> {
	let script = ScriptBuf::from_hex(script_hex)
		.map_err(|e| format!("invalid hex: {}", e))?;
	Ok(script.to_asm_string())
}

/// Run the given script.
///
/// Fields on the return value are:
/// - success: bool
/// - final_stack: list of hex stack items after execution
/// - error: (optional) error that caused execution halt
/// - last_opcode: (optional) last opcode run before error produced
/// - stats: execution runtime statistics with following fields:
///   - max_nb_stack_items
///   - max_stack_size
///   - max_stack_item_size
///   - start_validation_weight
///   - validation_weight
#[wasm_bindgen]
pub fn run_script(script_asm: &str) -> Result<JsValue, JsValue> {
	console_error_panic_hook::set_once();

	let script = ScriptBuf::parse_asm(script_asm)
		.map_err(|e| format!("error parsing script: {:?}", e))?;

	let mut exec = Exec::new(
		ExecCtx::Tapscript,
		Options::default(),
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
		&script,
		vec![],
	).map_err(|e| format!("error creating exec: {:?}", e))?;

	
	loop {
		if let Err(res) = exec.exec_next() {
			let res = res.clone();
			let mut ret = json!({
				"success": res.success,
				"final_stack": res.final_stack.iter()
					.map(|i| i.as_hex().to_string())
					.collect::<Vec<_>>(),
				"stats": serde_json::to_value(&exec.stats()).unwrap(),
			});
			if !res.success {
				let obj = ret.as_object_mut().unwrap();
				obj.insert(
					"last_opcode".into(),
					res.opcode.map(|o| o.to_string()).unwrap_or_default().into(),
				);
				obj.insert(
					"error".into(), res.error.map(|o| format!("{:?}", o)).unwrap_or_default().into(),
				);
			}

			return Ok(serde_wasm_bindgen::to_value(&ret).unwrap())
		}
	}
}
