#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MaxMalicious(usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReconstructionLowerBound(usize);

// ----- MaxMalicious conversions -----
impl MaxMalicious {
    pub fn get(self) -> usize {
        self.0
    }
}

impl ReconstructionLowerBound {
    pub fn get(self) -> usize {
        self.0
    }
}

impl From<usize> for MaxMalicious {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

impl From<MaxMalicious> for usize {
    fn from(value: MaxMalicious) -> Self {
        value.0
    }
}

// ----- ReconstructionLowerBound conversions -----

impl From<usize> for ReconstructionLowerBound {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

impl From<ReconstructionLowerBound> for usize {
    fn from(value: ReconstructionLowerBound) -> Self {
        value.0
    }
}
