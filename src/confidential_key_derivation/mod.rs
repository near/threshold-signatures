//! Confidential Key Derivation (CKD) protocol.
//!
//! This module provides the implementation of the Confidential Key Derivation (CKD) protocol,
//! which allows a client to derive a unique key for a specific application without revealing
//! the application identifier to the key derivation service.
//!
//! The protocol is based on a combination of Oblivious Transfer (OT) and Diffie-Hellman key exchange.
//!
//! For more details, refer to the `confidential_key_derivation.md` document in the `docs` folder.

use borsh::{BorshDeserialize, BorshSerialize};
use frost_secp256k1::{keys::SigningShare, Secp256K1Sha256, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
pub mod protocol;

#[derive(Clone, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct AppId(Arc<[u8]>);

impl Serialize for AppId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_bytes::Serialize::serialize(&self.0[..], serializer)
    }
}

impl<'de> Deserialize<'de> for AppId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v: Vec<u8> = serde_bytes::Deserialize::deserialize(deserializer)?;
        Ok(AppId(Arc::from(v)))
    }
}

impl From<Vec<u8>> for AppId {
    fn from(id: Vec<u8>) -> Self {
        Self(id.into_boxed_slice().into())
    }
}

impl AppId {
    pub fn new(id: impl AsRef<[u8]>) -> Self {
        Self(Arc::from(id.as_ref()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Arc<[u8]> {
        self.0
    }
}

impl AsRef<[u8]> for AppId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for AppId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

impl BorshSerialize for AppId {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // serialize as Vec<u8>
        let bytes: &[u8] = &self.0;
        borsh::BorshSerialize::serialize(&(bytes.len() as u32), writer)?;
        writer.write_all(bytes)
    }
}

impl BorshDeserialize for AppId {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let len = u32::deserialize_reader(reader)? as usize;
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        Ok(AppId::from(buf))
    }
}

/// Key Pairs containing secret share of the participant along with the master verification key
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeygenOutput {
    pub private_share: SigningShare,
    pub public_key: VerifyingKey,
}

pub(crate) type CoefficientCommitment = frost_core::keys::CoefficientCommitment<Secp256K1Sha256>;
pub(crate) type Element = frost_core::Element<Secp256K1Sha256>;
pub(crate) type Scalar = frost_core::Scalar<Secp256K1Sha256>;

/// The output of the confidential key derivation protocol when run by the coordinator
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CKDCoordinatorOutput {
    big_y: CoefficientCommitment,
    big_c: CoefficientCommitment,
}

impl CKDCoordinatorOutput {
    pub fn new(big_y: Element, big_c: Element) -> Self {
        CKDCoordinatorOutput {
            big_y: CoefficientCommitment::new(big_y),
            big_c: CoefficientCommitment::new(big_c),
        }
    }

    /// Outputs big_y
    pub fn big_y(&self) -> CoefficientCommitment {
        self.big_y
    }

    /// Outputs big_c
    pub fn big_c(&self) -> CoefficientCommitment {
        self.big_c
    }

    /// Takes a secret scalar and returns
    /// s <- C  − a  ⋅ Y = msk ⋅ H ( app_id )
    pub fn unmask(&self, secret_scalar: Scalar) -> CoefficientCommitment {
        CoefficientCommitment::new(self.big_c.value() - self.big_y.value() * secret_scalar)
    }
}

/// None for participants and Some for coordinator
pub type CKDOutput = Option<CKDCoordinatorOutput>;

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::config;
    use bincode::serde::{decode_from_slice, encode_to_vec};
    use borsh::BorshDeserialize;
    use rand::{rng, RngCore};
    use serde_json;

    #[test]
    fn test_app_id_display() {
        let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let app_id = AppId::new(bytes.clone());
        assert_eq!(app_id.to_string(), "deadbeef");
        assert_eq!(app_id.as_bytes(), &bytes[..]);
    }

    #[test]
    fn test_serde_json_roundtrip() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let original = AppId::new(bytes.clone());

        let json = serde_json::to_string(&original).unwrap();
        let decoded: AppId = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, original);
        assert_eq!(decoded.as_bytes(), &bytes[..]);
    }

    #[test]
    fn test_borsh_roundtrip() {
        let test_cases = vec![
            vec![],                        // empty
            vec![0x01],                    // single byte
            vec![0xDE, 0xAD, 0xBE, 0xEF],  // normal
            (0..255).collect::<Vec<u8>>(), // moderate size
        ];

        for bytes in test_cases {
            let original = AppId::new(bytes.clone());
            let mut buf = vec![];
            borsh::BorshSerialize::serialize(&original, &mut buf).unwrap();

            let decoded = AppId::deserialize_reader(&mut buf.as_slice()).unwrap();
            assert_eq!(decoded, original);
            assert_eq!(decoded.as_bytes(), &bytes[..]);
        }

        // Very large random array
        let mut rng = rng();
        let mut large_bytes = vec![0u8; 10_000];
        rng.fill_bytes(&mut large_bytes);
        let original = AppId::new(large_bytes.clone());
        let mut buf = vec![];
        borsh::BorshSerialize::serialize(&original, &mut buf).unwrap();
        let decoded = AppId::deserialize_reader(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.as_bytes(), &large_bytes[..]);
    }

    #[test]
    fn test_bincode_roundtrip() {
        let test_bytes = vec![0xAB, 0xCD, 0xEF];
        let original = AppId::new(test_bytes.clone());

        // Encode using bincode’s binary format
        let encoded = encode_to_vec(&original, config::standard()).expect("bincode encode");

        // Decode back into AppId
        let (decoded, _len): (AppId, usize) =
            decode_from_slice(&encoded, config::standard()).expect("bincode decode");

        assert_eq!(decoded, original);
        assert_eq!(decoded.as_bytes(), &test_bytes[..]);
    }

    #[test]
    fn test_failure_cases() {
        // Corrupted Borsh data
        let corrupted = vec![0, 1]; // length prefix too short
        assert!(AppId::deserialize_reader(&mut corrupted.as_slice()).is_err());

        let corrupted_long = vec![0xFF; 5]; // invalid length prefix
        assert!(AppId::deserialize_reader(&mut corrupted_long.as_slice()).is_err());

        // Corrupted JSON
        let invalid_json = "{ invalid json }";
        let result: Result<AppId, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }
}
