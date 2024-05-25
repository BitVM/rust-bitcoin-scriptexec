use crate::{read_scriptint, ExecError};
use alloc::rc::Rc;
use bitcoin::script;
use core::cell::RefCell;
use core::cmp::PartialEq;
use core::slice::Iter;
use std::iter::Map;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StackEntry {
    Num(i64),
    StrRef(Rc<RefCell<Vec<u8>>>),
}

#[derive(Clone, Eq, Debug, PartialEq)]
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

    pub fn from_u8_vec(v: Vec<Vec<u8>>) -> Self {
        let mut res = Self::new();
        for entry in v {
            res.0.push(StackEntry::StrRef(Rc::new(RefCell::new(entry))));
        }
        res
    }

    pub fn top(&self, offset: isize) -> Result<&StackEntry, ExecError> {
        debug_assert!(offset < 0, "offsets should be < 0");
        self.0
            .len()
            .checked_sub(offset.abs() as usize)
            .and_then(|i| Some(&self.0[i]))
            .ok_or(ExecError::InvalidStackOperation)
    }

    pub fn topstr(&self, offset: isize) -> Result<Vec<u8>, ExecError> {
        let entry = self.top(offset)?;
        match entry {
            StackEntry::Num(v) => Ok(script::scriptint_vec(*v)),
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
            StackEntry::Num(v) => Ok(script::scriptint_vec(v)),
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
            StackEntry::Num(v) => script::scriptint_vec(*v),
            StackEntry::StrRef(v) => v.borrow().to_vec(),
        })
    }

    pub fn get(&self, index: usize) -> Vec<u8> {
        match &self.0[index] {
            StackEntry::Num(v) => script::scriptint_vec(*v),
            StackEntry::StrRef(v) => v.borrow().to_vec(),
        }
    }
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}
