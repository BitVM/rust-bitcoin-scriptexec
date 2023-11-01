

use bitcoin::{ScriptBuf, Transaction};
use bitcoin::hex::DisplayHex;
use serde_json::json;
use wasm_bindgen::prelude::*;

use crate::*;

/// Run the given script.
///
/// Fields on the return value are:
/// - success: bool
/// - final_stack: list of hex stack items after execution
/// - error: (optional) error that caused execution halt
/// - last_opcode: (optional) last opcode run before error produced
#[wasm_bindgen]
pub fn run_script(script_asm: &str) -> Result<JsValue, JsValue> {
	console_error_panic_hook::set_once();

	let script = ScriptBuf::parse_asm(script_asm)
		.map_err(|e| format!("error parsing script: {:?}", e))?;

	let mut exec = Exec::new(
		ExecCtx::Tapscript,
		Options {
			require_minimal: true,
			verify_cltv: true,
			verify_csv: true,
			verify_minimal_if: true,
		},
		TxTemplate {
			tx: Transaction {
				version: bitcoin::transaction::Version::TWO,
				lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
				input: vec![],
				output: vec![],
			},
			prevouts: vec![],
			input_idx: 0,

		},
		&script,
		vec![],
	).map_err(|e| format!("error creating exec: {:?}", e))?;

	
	loop {
		if let Err(res) = exec.exec_next() {
			let mut ret = json!({
				"success": res.success,
				"final_stack": res.final_stack.iter()
					.map(|i| i.as_hex().to_string())
					.collect::<Vec<_>>(),
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
