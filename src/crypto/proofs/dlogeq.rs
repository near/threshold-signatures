use rand_core::CryptoRngCore;

use crate::crypto::ciphersuite::{Ciphersuite, Element};

use frost_core::{serialization::SerializableScalar, Field, Group};

use super::{encode_two_points, strobe_transcript::Transcript};

/// The label we use for hashing the statement.
const STATEMENT_LABEL: &[u8] = b"dlogeq proof statement";
/// The label we use for hashing the first prover message.
const COMMITMENT_LABEL: &[u8] = b"dlogeq proof commitment";
/// The label we use for generating the challenge.
const CHALLENGE_LABEL: &[u8] = b"dlogeq proof challenge";

/// The public statement for this proof.
///
/// This statement claims knowledge of a scalar that's the discrete logarithm
/// of one point under the standard generator, and of another point under an alternate generator.
#[derive(Clone, Copy)]
pub struct Statement<'a, C: Ciphersuite> {
    pub public0: &'a Element<C>,
    pub generator1: &'a Element<C>,
    pub public1: &'a Element<C>,
}

fn element_into_or_panic<C: Ciphersuite>(point: &Element<C>, label: &[u8]) -> Vec<u8> {
    let mut enc = Vec::new();
    match <C::Group as Group>::serialize(point) {
        Ok(ser) => {
            enc.extend_from_slice(label);
            enc.extend_from_slice(ser.as_ref());
        }
        _ => panic!("Expected non-identity element"),
    };
    enc
}

impl<C: Ciphersuite> Statement<'_, C> {
    /// Calculate the homomorphism we want to prove things about.
    fn phi(&self, x: &SerializableScalar<C>) -> (Element<C>, Element<C>) {
        (C::Group::generator() * x.0, *self.generator1 * x.0)
    }

    /// Encode into Vec<u8>: some sort of serialization
    fn encode(&self) -> Vec<u8> {
        let mut enc = Vec::new();
        enc.extend_from_slice(b"statement:");
        // None of the following calls should panic as neither public and generator are identity
        let ser0 = element_into_or_panic::<C>(self.public0, b"public 0:");
        let ser1 = element_into_or_panic::<C>(self.generator1, b"generator 1:");
        let ser2 = element_into_or_panic::<C>(self.public1, b"public 1:");
        enc.extend_from_slice(&ser0);
        enc.extend_from_slice(&ser1);
        enc.extend_from_slice(&ser2);
        enc
    }
}

/// The private witness for this proof.
///
/// This holds the scalar the prover needs to know.
#[derive(Clone, Copy)]
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

/// Prove that a witness satisfies a given statement.
///
/// We need some randomness for the proof, and also a transcript, which is
/// used for the Fiat-Shamir transform.
pub fn prove<C: Ciphersuite>(
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    witness: Witness<C>,
) -> Proof<C> {
    transcript.message(STATEMENT_LABEL, &statement.encode());

    let k = SerializableScalar::<C>(<C::Group as Group>::Field::random(rng));
    let big_k = statement.phi(&k);

    transcript.message(
        COMMITMENT_LABEL,
        &encode_two_points::<C>(&big_k.0, &big_k.1),
    );
    let mut rng = transcript.challenge_then_build_rng(CHALLENGE_LABEL);
    let e = <C::Group as Group>::Field::random(&mut rng);

    let s = k.0 + e * witness.x.0;
    Proof {
        e: SerializableScalar::<C>(e),
        s: SerializableScalar::<C>(s),
    }
}

/// Verify that a proof attesting to the validity of some statement.
///
/// We use a transcript in order to verify the Fiat-Shamir transformation.
#[must_use]
pub fn verify<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    proof: &Proof<C>,
) -> bool {
    transcript.message(STATEMENT_LABEL, &statement.encode());

    let (phi0, phi1) = statement.phi(&proof.s);
    let big_k0 = phi0 - *statement.public0 * proof.e.0;
    let big_k1 = phi1 - *statement.public1 * proof.e.0;

    transcript.message(COMMITMENT_LABEL, &encode_two_points::<C>(&big_k0, &big_k1));
    let mut rng = transcript.challenge_then_build_rng(CHALLENGE_LABEL);
    let e = <C::Group as Group>::Field::random(&mut rng);

    e == proof.e.0
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

        let big_h = ProjectivePoint::GENERATOR * Scalar::generate_biased(&mut OsRng);
        let statement = Statement::<Secp256K1Sha256> {
            public0: &(ProjectivePoint::GENERATOR * x),
            generator1: &big_h,
            public1: &(big_h * x),
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
        );

        let ok = verify(&mut transcript.fork(b"party", &[1]), statement, &proof);

        assert!(ok);
    }
}
