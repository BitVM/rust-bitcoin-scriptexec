use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;

use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::taproot::TapLeafHash;
use bitcoin::{ScriptBuf, Transaction};
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
    /// Whether to output result in JSON.
    #[arg(long)]
    json: bool,
}

/// A wrapper for the stack types to print them better.
struct FmtStack<'a>(&'a Stack);
impl<'a> fmt::Display for FmtStack<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.0.iter_str().rev().peekable();
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

    let script_asm = std::fs::read_to_string(args.script_path).expect("error reading script file");
    let script = ScriptBuf::parse_asm(&script_asm).expect("error parsing script");
    println!("Script in hex: {}", script.as_bytes().to_lower_hex_string());
    println!("Script size: {} bytes", script.as_bytes().len());

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
    )
    .expect("error creating exec");

    const SEP: &str = "--------------------------------------------------";

    let mut out = io::stdout();
    println!("{}", SEP);
    loop {
        if args.debug {
            if args.json {
                let step = json::RunStep {
                    remaining_script: exec.remaining_script(),
                    stack: &exec.stack().iter_str().collect::<Vec<Vec<u8>>>(),
                    altstack: &exec.altstack().iter_str().collect::<Vec<Vec<u8>>>(),
                    stats: Some(exec.stats()),
                };
                serde_json::to_writer(&out, &step).expect("I/O error");
                out.write_all(&['\n' as u8]).expect("I/O error");
            } else {
                println!(
                    "Remaining script: {}",
                    exec.remaining_script().to_asm_string()
                );
                println!("Stack: {}", FmtStack(&exec.stack()));
                println!("AltStack: {}", FmtStack(&exec.altstack()));
                println!("{}", SEP);
            }
        }

        if exec.exec_next().is_err() {
            break;
        }
    }

    let res = exec.result().unwrap().clone();
    if args.json {
        let ret = json::RunResult {
            success: res.success,
            error: res.error.map(|e| format!("{:?}", e)), //TODO(stevenroose) fmt::Display
            opcode: res.opcode,
            final_stack: &res.final_stack.iter_str().collect::<Vec<Vec<u8>>>(),
            stats: Some(exec.stats()),
        };
        serde_json::to_writer(&out, &ret).expect("I/O error");
    } else {
        println!("Execution ended. Success: {}", res.success);
        print!("Final stack: {}", FmtStack(&res.final_stack));
        println!();
        if !res.success {
            println!("Failed on opcode: {:?}", res.opcode);
            println!("Error: {:?}", res.error);
        }
        println!("Stats:\n{:#?}", exec.stats());
        println!("Time elapsed: {}ms", start.elapsed().as_millis());
    }
    return Ok(());
}

fn main() {
    if let Err(e) = inner_main() {
        eprintln!("ERROR: {}", e);
    }
}
