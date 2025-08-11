use crate::{
    crypto::ciphersuite::{Ciphersuite, Element},
    protocol::ProtocolError,
};
use frost_core::{serialization::SerializableScalar, Field, Group};

use super::strobe_transcript::Transcript;
use rand_core::CryptoRngCore;

/// The label we use for hashing the statement.
const STATEMENT_LABEL: &[u8] = b"dlog proof statement";
/// The label we use for hashing the first prover message.
const COMMITMENT_LABEL: &[u8] = b"dlog proof commitment";
/// The label we use for generating the challenge.
const CHALLENGE_LABEL: &[u8] = b"dlog proof challenge";
/// A string used to extend an encoding
const ENCODE_LABEL_STATEMENT: &[u8] = b"statement:";
/// A string used to extend an encoding
const ENCODE_LABEL_PUBLIC: &[u8] = b"public:";

/// The public statement for this proof.
///
/// This statement claims knowledge of the discrete logarithm of some point.
#[derive(Clone, Copy)]
pub struct Statement<'a, C: Ciphersuite> {
    pub public: &'a Element<C>,
}

impl<C: Ciphersuite> Statement<'_, C> {
    /// Calculate the homomorphism we want to prove things about.
    fn phi(&self, x: &SerializableScalar<C>) -> Element<C> {
        C::Group::generator() * x.0
    }

    /// Encode into Vec<u8>: some sort of serialization
    fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut enc = Vec::new();
        enc.extend_from_slice(ENCODE_LABEL_STATEMENT);

        match <C::Group as Group>::serialize(self.public) {
            Ok(ser) => {
                enc.extend_from_slice(ENCODE_LABEL_PUBLIC);
                enc.extend_from_slice(ser.as_ref());
            }
            _ => return Err(ProtocolError::PointSerialization),
        };
        Ok(enc)
    }
}

/// The private witness for this proof.
/// This holds the scalar the prover needs to know.
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct Witness<C: Ciphersuite> {
    pub x: SerializableScalar<C>,
}

/// Represents a proof of the statement.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct Proof<C: Ciphersuite> {
    e: SerializableScalar<C>,
    s: SerializableScalar<C>,
}

/// Encodes an EC point into a vec including the identity point.
/// Should be used with HIGH precaution as it allows serializing the identity point
/// deviating from the standard
fn encode_point<C: Ciphersuite>(point: &Element<C>) -> Result<Vec<u8>, ProtocolError> {
    // Need to create a serialization containing the all zero strings
    let size = C::Group::serialize(&C::Group::generator())
        .unwrap()
        .as_ref()
        .len();
    // Serializing the identity might fail!
    // this is a workaround to be able to serialize even this infinity point.
    let ser = match <<C as frost_core::Ciphersuite>::Group as Group>::Serialization::try_from(vec![
            0u8;
            size
        ]) {
        Ok(ser) => ser,
        _ => return Err(ProtocolError::ErrorEncoding),
    };
    Ok(C::Group::serialize(point).unwrap_or(ser).as_ref().to_vec())
}

/// Prove that a witness satisfies a given statement.
///
/// We need some randomness for the proof, and also a transcript, which is
/// used for the Fiat-Shamir transform.
pub fn prove<C: Ciphersuite>(
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    witness: Witness<C>,
) -> Result<Proof<C>, ProtocolError> {
    transcript.message(STATEMENT_LABEL, &statement.encode()?);

    let k = <C::Group as Group>::Field::random(rng);
    let big_k = statement.phi(&SerializableScalar(k));

    transcript.message(COMMITMENT_LABEL, &encode_point::<C>(&big_k)?);
    let mut rng = transcript.challenge_then_build_rng(CHALLENGE_LABEL);
    let e = <C::Group as Group>::Field::random(&mut rng);

    let s = k + e * witness.x.0;
    Ok(Proof {
        e: SerializableScalar(e),
        s: SerializableScalar(s),
    })
}

/// Verify that a proof attesting to the validity of some statement.
///
/// We use a transcript in order to verify the Fiat-Shamir transformation.
pub fn verify<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    proof: &Proof<C>,
) -> Result<bool, ProtocolError> {
    transcript.message(STATEMENT_LABEL, &statement.encode()?);

    let big_k: Element<C> = statement.phi(&proof.s) - *statement.public * proof.e.0;

    transcript.message(COMMITMENT_LABEL, &encode_point::<C>(&big_k)?);
    let mut rng = transcript.challenge_then_build_rng(CHALLENGE_LABEL);
    let e = <C::Group as Group>::Field::random(&mut rng);

    Ok(e == proof.e.0)
}

#[cfg(test)]
mod test {
    use rand_core::OsRng;

    use super::*;
    use frost_secp256k1::Secp256K1Sha256;
    use k256::{ProjectivePoint, Scalar};

    #[test]
    fn test_valid_proof_verifies() {
        let x = Scalar::generate_biased(&mut OsRng);

        let statement = Statement::<Secp256K1Sha256> {
            public: &(ProjectivePoint::GENERATOR * x),
        };
        let witness = Witness {
            x: SerializableScalar::<Secp256K1Sha256>(x),
        };

        let transcript = Transcript::new(b"protocol");

        let proof = prove(
            &mut OsRng,
            &mut transcript.fork(b"party", &[1]),
            statement,
            witness,
        )
        .unwrap();

        let ok = verify(&mut transcript.fork(b"party", &[1]), statement, &proof).unwrap();

        assert!(ok);
    }
}
