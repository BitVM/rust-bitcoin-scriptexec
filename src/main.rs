
use std::fmt;
use std::path::PathBuf;

use bitcoin::{ScriptBuf, Transaction};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::taproot::TapLeafHash;
use clap::Parser;

use bitcoin_scriptexec::*;

#[derive(Parser)]
#[command(author = "Steven Roose <steven@roose.io>", version, about)]
struct Args {
	/// filepath to script ASM file
	#[arg(required = true)]
	script_path: PathBuf,
	/// Whether to print debug info
	#[arg(long)]
	debug: bool,
}

struct FmtStack<'a>(&'a Vec<Vec<u8>>);
impl<'a> fmt::Display for FmtStack<'a> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let mut iter = self.0.iter().rev().peekable();
		while let Some(item) = iter.next() {
			write!(f, "<{}>", item.as_hex())?;
			if iter.peek().is_some() {
				write!(f, " ")?;
			}
		}
		Ok(())
	}
}

fn inner_main() -> Result<(), String> {
	let args = Args::parse();

	let script_asm = std::fs::read_to_string(args.script_path)
		.expect("error reading script file");
	let script = ScriptBuf::parse_asm(&script_asm)
		.expect("error parsing script");

	let start = std::time::Instant::now();
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
		script,
		vec![],
	).expect("error creating exec");

	
	const SEP: &str = "--------------------------------------------------";
	println!("{}", SEP);
	loop {
		if args.debug {
			println!("Remaining script: {}", exec.remaining_script().to_asm_string());
			println!("Stack: {}", FmtStack(exec.stack()));
			println!("AltStack: {}", FmtStack(exec.altstack()));
			println!("{}", SEP);
		}

		if exec.exec_next().is_err() {
			break;
		}
	}

	let res = exec.result().unwrap().clone();
	println!("Execution ended. Succes: {}", res.success);
	print!("Final stack: {}", FmtStack(&res.final_stack));
	println!("");
	if !res.success {
		println!("Failed on opcode: {:?}", res.opcode);
		println!("Error: {:?}", res.error);
	}
	println!("Stats:\n{:#?}", exec.stats());
	println!("Time elapsed: {}ms", start.elapsed().as_millis());
	return Ok(());
}

fn main() {
	if let Err(e) = inner_main() {
		eprintln!("ERROR: {}", e);
	}
}
