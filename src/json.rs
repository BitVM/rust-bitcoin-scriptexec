use std::fmt;

use bitcoin::hex::DisplayHex;
use bitcoin::{Opcode, Script};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

use crate::ExecStats;

/// Simple utility wrapper to serde-serialize using [fmt::Display].
struct FmtSer<'a, T: fmt::Display>(&'a T);
impl<'a, T: fmt::Display> Serialize for FmtSer<'a, T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&self.0)
    }
}

/// Wrapper to fmt::Display a Script as ASM.
struct ScriptAsm<'a>(&'a Script);
impl<'a> fmt::Display for ScriptAsm<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt_asm(f)
    }
}

/// Wrapper to serialize a stack as hex elements.
struct StackSer<'a>(&'a [Vec<u8>]);
impl<'a> Serialize for StackSer<'a> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for i in self.0.iter() {
            seq.serialize_element(&FmtSer(&i.as_hex()))?;
        }
        seq.end()
    }
}

pub struct RunStep<'a> {
    pub remaining_script: &'a Script,
    pub stack: &'a [Vec<u8>],
    pub altstack: &'a [Vec<u8>],
    pub stats: Option<&'a ExecStats>,
}

impl<'a> Serialize for RunStep<'a> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry(
            "remaining_script_hex",
            &FmtSer(&self.remaining_script.as_bytes().as_hex()),
        )?;
        m.serialize_entry(
            "remaining_script_asm",
            &FmtSer(&ScriptAsm(self.remaining_script)),
        )?;
        m.serialize_entry("stack", &StackSer(self.stack))?;
        m.serialize_entry("altstack", &StackSer(self.altstack))?;
        if let Some(ref stats) = self.stats {
            m.serialize_entry("stats", stats)?;
        }
        m.end()
    }
}

pub struct RunResult<'a> {
    pub success: bool,
    pub error: Option<String>,
    pub opcode: Option<Opcode>,
    pub final_stack: &'a [Vec<u8>],
    pub stats: Option<&'a ExecStats>,
}

impl<'a> Serialize for RunResult<'a> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("success", &self.success)?;
        if let Some(ref err) = self.error {
            m.serialize_entry("error", err)?;
        }
        if let Some(opcode) = self.opcode {
            m.serialize_entry("opcode", &FmtSer(&opcode))?;
        }
        m.serialize_entry("final_stack", &StackSer(self.final_stack))?;
        if let Some(ref stats) = self.stats {
            m.serialize_entry("stats", stats)?;
        }
        m.end()
    }
}
