use crate::{read_scriptint, ExecError};
use alloc::rc::Rc;
use bitcoin::script::write_scriptint;
use core::cell::RefCell;
use core::cmp::PartialEq;
use core::slice::Iter;
use std::iter::Map;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StackEntry {
    Num(i64),
    StrRef(Rc<RefCell<Vec<u8>>>),
}

/// Returns minimally encoded scriptint as a byte vector.
pub fn scriptint_vec(n: i64) -> Vec<u8> {
    let mut buf = [0u8; 8];
    let len = write_scriptint(&mut buf, n);
    buf[0..len].to_vec()
}

impl StackEntry {
    // This assumes the StackEntry fit in a u32 and will pad it with leading zeros to 4 bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            StackEntry::Num(v) => scriptint_vec(*v),
            StackEntry::StrRef(v) => {
                let v = v.borrow().to_vec();
                assert!(
                    v.len() <= 4,
                    "There should not be entries with more than 32 bits on the Stack at this point"
                );
                v
            }
        }
    }
}

#[derive(Clone, Debug, Default, Eq)]
pub struct Stack(Vec<StackEntry>);

impl Stack {
    pub fn new() -> Self {
        Self(Vec::with_capacity(1000))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn last(&self) -> Result<Vec<u8>, ExecError> {
        self.topstr(-1)
    }

    pub fn top(&self, offset: isize) -> Result<&StackEntry, ExecError> {
        debug_assert!(offset < 0, "offsets should be < 0");
        self.0
            .len()
            .checked_sub(offset.unsigned_abs())
            .map(|i| &self.0[i])
            .ok_or(ExecError::InvalidStackOperation)
    }

    pub fn topstr(&self, offset: isize) -> Result<Vec<u8>, ExecError> {
        let entry = self.top(offset)?;
        match entry {
            StackEntry::Num(v) => Ok(scriptint_vec(*v)),
            StackEntry::StrRef(v) => Ok(v.borrow().to_vec()),
        }
    }

    pub fn topnum(&self, offset: isize, require_minimal: bool) -> Result<i64, ExecError> {
        let entry = self.top(offset)?;
        match entry {
            StackEntry::Num(v) => {
                if *v <= i32::MAX as i64 {
                    Ok(*v)
                } else {
                    Err(ExecError::ScriptIntNumericOverflow)
                }
            }
            StackEntry::StrRef(v) => Ok(read_scriptint(v.borrow().as_slice(), 4, require_minimal)?),
        }
    }

    pub fn pushnum(&mut self, num: i64) {
        self.0.push(StackEntry::Num(num));
    }

    pub fn pushstr(&mut self, v: &[u8]) {
        self.0
            .push(StackEntry::StrRef(Rc::new(RefCell::new(v.to_vec()))));
    }

    pub fn push(&mut self, v: StackEntry) {
        self.0.push(v);
    }

    pub fn needn(&self, min_nb_items: usize) -> Result<(), ExecError> {
        if self.len() < min_nb_items {
            Err(ExecError::InvalidStackOperation)
        } else {
            Ok(())
        }
    }

    pub fn popn(&mut self, n: usize) -> Result<(), ExecError> {
        for _ in 0..n {
            self.0.pop().ok_or(ExecError::InvalidStackOperation)?;
        }
        Ok(())
    }

    pub fn pop(&mut self) -> Option<StackEntry> {
        self.0.pop()
    }

    pub fn popstr(&mut self) -> Result<Vec<u8>, ExecError> {
        let entry = self.0.pop().ok_or(ExecError::InvalidStackOperation)?;
        match entry {
            StackEntry::Num(v) => Ok(scriptint_vec(v)),
            StackEntry::StrRef(v) => Ok(v.borrow().to_vec()),
        }
    }

    pub fn popnum(&mut self, require_minimal: bool) -> Result<i64, ExecError> {
        let entry = self.0.pop().ok_or(ExecError::InvalidStackOperation)?;
        match entry {
            StackEntry::Num(v) => {
                if v <= i32::MAX as i64 {
                    Ok(v)
                } else {
                    Err(ExecError::ScriptIntNumericOverflow)
                }
            }
            StackEntry::StrRef(v) => Ok(read_scriptint(v.borrow().as_slice(), 4, require_minimal)?),
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn remove(&mut self, v: usize) {
        self.0.remove(v);
    }

    pub fn iter_str(&self) -> Map<Iter<StackEntry>, fn(&StackEntry) -> Vec<u8>> {
        self.0.iter().map(|v| match v {
            StackEntry::Num(v) => scriptint_vec(*v),
            StackEntry::StrRef(v) => v.borrow().to_vec(),
        })
    }

    pub fn get(&self, index: usize) -> Vec<u8> {
        match &self.0[index] {
            StackEntry::Num(v) => scriptint_vec(*v),
            StackEntry::StrRef(v) => v.borrow().to_vec(),
        }
    }

    pub fn from_u8_vec(v: Vec<Vec<u8>>) -> Self {
        let mut res = Self::new();
        for entry in v {
            res.0.push(StackEntry::StrRef(Rc::new(RefCell::new(entry))));
        }
        res
    }

    pub fn as_v8_vec(&self) -> Vec<Vec<u8>> {
        self.0.iter().map(|entry| entry.as_bytes()).collect()
    }
}

impl PartialEq for Stack {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .zip(other.0.iter())
                .all(|(a, b)| a.as_bytes() == b.as_bytes())
    }
}

/// A wrapper for the stack types to print them in Bitcoin Script ASM format.
impl std::fmt::Display for Stack {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut iter = self.0.iter().rev().peekable();
        while let Some(entry) = iter.next() {
            match entry {
                StackEntry::Num(n) => {
                    write!(f, "{}", n)?;
                }
                StackEntry::StrRef(v) => {
                    let bytes = v.borrow();
                    if bytes.is_empty() {
                        write!(f, "0")?;
                    } else if let Ok(num) = read_scriptint(bytes.as_slice(), 4, false) {
                        // Try to interpret as scriptint for cleaner display
                        write!(f, "{}", num)?;
                    } else {
                        // Display as raw hex (no 0x prefix, matching Bitcoin Script ASM)
                        for byte in bytes.iter() {
                            write!(f, "{:02x}", byte)?;
                        }
                    }
                }
            }
            if iter.peek().is_some() {
                write!(f, " ")?;
            }
        }
        Ok(())
    }
}
