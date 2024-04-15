///  A data type to abstract out the condition stack during script execution.
///
/// Conceptually it acts like a vector of booleans, one for each level of nested
/// IF/THEN/ELSE, indicating whether we're in the active or inactive branch of
/// each.
///
/// The elements on the stack cannot be observed individually; we only need to
/// expose whether the stack is empty and whether or not any false values are
/// present at all. To implement OP_ELSE, a toggle_top modifier is added, which
/// flips the last value without returning it.
///
/// This uses an optimized implementation that does not materialize the
/// actual stack. Instead, it just stores the size of the would-be stack,
/// and the position of the first false value in it.
pub struct ConditionStack {
    /// The size of the implied stack.
    size: usize,
    /// The position of the first false value on the implied stack,
    /// or NO_FALSE if all true.
    first_false_pos: usize,
}

impl ConditionStack {
    /// A constant for first_false_pos to indicate there are no falses.
    const NO_FALSE: usize = usize::MAX;

    pub fn new() -> Self {
        Self {
            size: 0,
            first_false_pos: Self::NO_FALSE,
        }
    }

    pub fn all_true(&self) -> bool {
        self.first_false_pos == Self::NO_FALSE
    }

    pub fn push(&mut self, v: bool) {
        if self.first_false_pos == Self::NO_FALSE && !v {
            // The stack consists of all true values, and a false is added.
            // The first false value will appear at the current size.
            self.first_false_pos = self.size;
        }
        self.size += 1;
    }

    /// Returns [false] if it was empty, [true] otherwise.
    ///
    /// Note that the popped value is not returned.
    pub fn pop(&mut self) -> bool {
        if self.size == 0 {
            false
        } else {
            self.size -= 1;
            if self.first_false_pos == self.size {
                // When popping off the first false value, everything becomes true.
                self.first_false_pos = Self::NO_FALSE;
            }
            true
        }
    }

    pub fn toggle_top(&mut self) -> bool {
        if self.size == 0 {
            false
        } else {
            if self.first_false_pos == Self::NO_FALSE {
                // The current stack is all true values; the first false will be the top.
                self.first_false_pos = self.size - 1;
            } else if self.first_false_pos == self.size - 1 {
                // The top is the first false value; toggling it will make everything true.
                self.first_false_pos = Self::NO_FALSE;
            } else {
                // There is a false value, but not on top. No action is needed as toggling
                // anything but the first false value is unobservable.
            }
            true
        }
    }
}
