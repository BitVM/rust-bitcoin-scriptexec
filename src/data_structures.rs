use crate::{read_scriptint, ExecError};
use alloc::rc::Rc;
use bitcoin::script;
use core::cell::RefCell;
use core::cmp::PartialEq;
use core::slice::Iter;
use serde::de::{self, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::iter::Map;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StackEntry {
    Num(i64),
    StrRef(Rc<RefCell<Vec<u8>>>),
}

impl StackEntry {
    #[deprecated(note = "Use `as_bytes` to avoid the borrow")]
    // This assumes the StackEntry fit in a u32 and will pad it with leading zeros to 4 bytes.
    pub fn serialize_to_bytes(self) -> Vec<u8> {
        self.as_bytes()
    }

    // This assumes the StackEntry fit in a u32 and will pad it with leading zeros to 4 bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            StackEntry::Num(v) => script::scriptint_vec(*v),
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

impl Serialize for StackEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.as_bytes())
    }
}

impl<'de> Deserialize<'de> for StackEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(StackEntryVisitor)
    }
}

struct StackEntryVisitor;

impl<'de> Visitor<'de> for StackEntryVisitor {
    type Value = StackEntry;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a byte array representing a StackEntry")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() <= 4 {
            Ok(StackEntry::StrRef(Rc::new(RefCell::new(v.to_vec()))))
        } else {
            Err(de::Error::invalid_value(Unexpected::Bytes(v), &self))
        }
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut vec = Vec::with_capacity(4);
        while let Some(value) = seq.next_element()? {
            vec.push(value);
        }

        if vec.len() <= 4 {
            Ok(StackEntry::StrRef(Rc::new(RefCell::new(vec))))
        } else {
            Err(de::Error::invalid_length(vec.len(), &self))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

    #[deprecated(note = "Use `as_v8_vec` to be symmetry")]
    // Will serialize the stack into a series of bytes such that every 4 bytes correspond to a u32
    // (or smaller) stack entry (smaller entries are padded with 0).
    pub fn serialize_to_bytes(self) -> Vec<u8> {
        let mut bytes = vec![];
        for entry in self.0 {
            bytes.extend(entry.serialize_to_bytes());
        }
        bytes
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

impl Default for Stack {
    fn default() -> Self {
        Self::new()
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

impl Eq for Stack {}

#[test]
fn test_stack_serialize_json() {
    let mut stack_0 = Stack::new();
    stack_0.pushnum(42);
    stack_0.pushstr(&[1, 2]);

    // Serialize it
    let serialized_stack = serde_json::to_string(&stack_0).expect("Failed to serialize Stack");

    // Deserialize it
    let mut stack_1: Stack =
        serde_json::from_str(&serialized_stack).expect("Failed to deserialize Stack");

    assert_eq!(stack_0, stack_1);
    assert_eq!(stack_0.popnum(true), stack_1.popnum(true));
    assert_eq!(stack_0.popstr(), stack_1.popstr());
}

#[test]
fn test_stack_serialize_bincode() {
    let mut stack_0 = Stack::new();
    stack_0.pushnum(42);
    stack_0.pushstr(&[1, 2]);

    // Serialize it
    let serialized_stack = bincode::serialize(&stack_0).expect("Failed to serialize Stack");

    // Deserialize it
    let mut stack_1: Stack =
        bincode::deserialize(&serialized_stack).expect("Failed to deserialize Stack");

    assert_eq!(stack_0, stack_1);
    assert_eq!(stack_0.popnum(true), stack_1.popnum(true));
    assert_eq!(stack_0.popstr(), stack_1.popstr());
}

#[test]
fn test_stack_entry_serialize_json() {
    let entry = StackEntry::Num(42);
    let serialized = serde_json::to_string(&entry).unwrap();
    let deserialized: StackEntry = serde_json::from_str(&serialized).unwrap();
    assert_eq!(entry.as_bytes(), deserialized.as_bytes());

    let entry = StackEntry::StrRef(Rc::new(RefCell::new(vec![1, 2, 3])));
    let serialized = serde_json::to_string(&entry).unwrap();
    let deserialized: StackEntry = serde_json::from_str(&serialized).unwrap();
    assert_eq!(entry, deserialized);
}

#[test]
fn test_stack_entry_serialize_bincode() {
    let entry = StackEntry::Num(42);
    let serialized = bincode::serialize(&entry).unwrap();
    let deserialized: StackEntry = bincode::deserialize(&serialized).unwrap();
    assert_eq!(entry.as_bytes(), deserialized.as_bytes());

    let entry = StackEntry::StrRef(Rc::new(RefCell::new(vec![1, 2, 3])));
    let serialized = bincode::serialize(&entry).unwrap();
    let deserialized: StackEntry = bincode::deserialize(&serialized).unwrap();
    assert_eq!(entry, deserialized);
}
