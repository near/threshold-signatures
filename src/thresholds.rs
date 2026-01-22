#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ThresholdAge {
    OldThreshold,
    NewThreshold,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Threshold {
    MaxFaulty(usize),
    MaxMalicious(usize),
}

// Add Restrictions for the thresholds
trait ThresholdRule {
    fn is_valid_threshold(threshold: &Threshold, active_participants: &usize) -> bool;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ThresholdRestrictionKind {
    Broadcast,
    DKG,
    Presigning,
    Signing,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct ThresholdRestriction {
    kind: ThresholdRestrictionKind,
    threshold: Threshold,
    age: ThresholdAge,
}

pub enum Schemes {
    ReliableBroadcast,
    DistributedKeyGeneration,
    KeyRefresh,
    KeyReshare,
    OTECDSATripleGeneration,
    OTECDSAPresigning,
    OTECDSASigning,
    RobustECDSAPresigning,
    RobustECDSASigning,
    FrostSigning,
    ConfidentialKeyDerivation,
}
