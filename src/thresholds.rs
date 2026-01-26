
use serde::{Deserialize, Serialize};

use crate::errors::ProtocolError;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct MaxMalicious(usize);

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct MaxFaulty(usize);

impl MaxMalicious {
    pub fn new(value: usize) -> Self{
        Self(value)
    }

    pub fn value(&self) -> usize {
        self.0
    }

    pub fn reconstruction_threshold(&self) -> Result<usize, ProtocolError> {
        self.0.checked_add(1).ok_or(ProtocolError::IntegerOverflow)
    }
}

pub trait ThresholdRestriction<T> {
    fn is_valid(&self, inputs: &T) -> bool;
}