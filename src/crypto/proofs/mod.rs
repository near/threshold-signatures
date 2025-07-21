use crate::crypto::ciphersuite::{Ciphersuite, Element};
use frost_core::Group;

/// Encodes an EC point into a vec including the identity point.
/// Should be used with HIGH precaution as it allows serializing the identity point
/// deviating from the standard
pub(crate) fn encode_point<C: Ciphersuite>(point: &Element<C>) -> Vec<u8> {
    // Need to create a serialization containing the all zero strings
    let size = C::Group::serialize(&C::Group::generator())
        .unwrap()
        .as_ref()
        .len();
    // Serializing the identity might fail!
    // this is a workaround to be able to serialize even this infinity point.
    let ser =
        match <<C as frost_core::Ciphersuite>::Group as Group>::Serialization::try_from(vec![
            0u8;
            size
        ]) {
            Ok(ser) => ser,
            _ => panic!("Should not raise error"),
        };
    C::Group::serialize(point)
        .unwrap_or_else(|_| ser)
        .as_ref()
        .to_vec()
}

/// Encodes two EC points into a vec including the identity point.
/// Should be used with HIGH precaution as it allows serializing the identity point
/// deviating from the standard
pub(crate) fn encode_two_points<C: Ciphersuite>(
    point_1: &Element<C>,
    point_2: &Element<C>,
) -> Vec<u8> {
    // Need to create a serialization containing the all zero strings
    let size = C::Group::serialize(&C::Group::generator())
        .unwrap()
        .as_ref()
        .len();
    // Serializing the identity might fail!
    // this is a workaround to be able to serialize even this infinity point.
    let ser =
        match <<C as frost_core::Ciphersuite>::Group as Group>::Serialization::try_from(vec![
            0u8;
            size
        ]) {
            Ok(ser) => ser,
            _ => panic!("Should not raise error"),
        };

    let ser_1 = C::Group::serialize(point_1)
        .unwrap_or_else(|_| ser)
        .as_ref()
        .to_vec();

    // Clone is not derived in Serialization type so I had to compute it again :(
    let ser =
        match <<C as frost_core::Ciphersuite>::Group as Group>::Serialization::try_from(vec![
            0u8;
            size
        ]) {
            Ok(ser) => ser,
            _ => panic!("Should not raise error"),
        };
    let ser_2 = C::Group::serialize(point_2)
        .unwrap_or_else(|_| ser)
        .as_ref()
        .to_vec();
    rmp_serde::encode::to_vec(&(ser_1, ser_2)).expect("failed to encode value")
}

pub mod dlog;
pub mod dlogeq;
mod strobe;
pub mod strobe_transcript;
