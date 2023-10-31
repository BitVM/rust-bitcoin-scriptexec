

use bitcoin::{ScriptBuf, Transaction};
use bitcoin::hex::DisplayHex;

use bitcoin_scriptexec::*;

fn main() {
	let start = std::time::Instant::now();
	let mut args = std::env::args().skip(1);

	let script_path = args.next().expect("first arg must be script file path");

	if script_path == "--help" {
		println!("Usage: btcexec <script-path> <witness>");
		return;
	}

	let script_asm = std::fs::read_to_string(script_path)
		.expect("error reading script file");
	let script = ScriptBuf::parse_asm(&script_asm)
		.expect("error parsing script");

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
	).expect("error creating exec");

	
	loop {
		if let Err(res) = exec.exec_next() {
			println!("Execution ended. Succes: {}", res.success);
			print!("Final stack: ");
			for item in res.final_stack {
				print!("{} ", item.as_hex());
			}
			println!("");
			if !res.success {
				println!("Failed on opcode: {:?}", res.opcode);
				println!("Error: {:?}", res.error);
			}
			println!("Time elapsed: {}ns", start.elapsed().as_nanos());
			return;
		}
	}
}
// pub struct ExecutionResult {
// 	pub success: bool,
// 	pub error: Option<ExecError>,
// 	pub opcode: Option<Opcode>,
// 	pub final_stack: Vec<Vec<u8>>,
// }
