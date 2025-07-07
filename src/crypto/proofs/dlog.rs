use crate::{
    crypto::ciphersuite::{
        Ciphersuite,
        Element,
        Scalar,
    },
};
use frost_core::{
    Group,
    Field,
};

use super::{
    encode_point,
    strobe_transcript::Transcript,
};
use rand_core::CryptoRngCore;

/// The label we use for hashing the statement.
const STATEMENT_LABEL: &[u8] = b"dlog proof statement";
/// The label we use for hashing the first prover message.
const COMMITMENT_LABEL: &[u8] = b"dlog proof commitment";
/// The label we use for generating the challenge.
const CHALLENGE_LABEL: &[u8] = b"dlog proof challenge";

/// The public statement for this proof.
///
/// This statement claims knowledge of the discrete logarithm of some point.
#[derive(Clone, Copy)]
pub struct Statement<'a, C: Ciphersuite> {
    pub public: &'a Element<C>,
}

impl<'a, C: Ciphersuite> Statement<'a, C> {
    /// Calculate the homomorphism we want to prove things about.
    fn phi(&self, x: &Scalar<C>) -> Element<C> {
        C::Group::generator() * *x
    }

    /// Encode into Vec<u8>: some sort of serialization
    pub fn encode(&self) -> Vec<u8>{
        let mut enc =  Vec::new();
        enc.extend_from_slice(b"statement:");

        match <C::Group as Group>::serialize(self.public){
            Ok(ser) => {
                enc.extend_from_slice(b"public:");
                enc.extend_from_slice(ser.as_ref().into());
            },
            _=> panic!("Expected non-identity element"),
        };
        enc
    }
}

/// The private witness for this proof.
/// This holds the scalar the prover needs to know.
#[derive(Clone, Copy)]
pub struct Witness<'a, C: Ciphersuite> {
    pub x: &'a Scalar<C>,
}

impl<'a, C: Ciphersuite> Witness<'a, C> {
    fn encode(&self) -> Vec<u8>{
        <C::Group as Group>::Field::serialize(self.x).as_ref().into()
    }
}

/// Represents a proof of the statement.
#[derive(Clone)]
pub struct Proof<C:Ciphersuite> {
    e: Scalar<C>,
    s: Scalar<C>,
}

/// Prove that a witness satisfies a given statement.
///
/// We need some randomness for the proof, and also a transcript, which is
/// used for the Fiat-Shamir transform.
pub fn prove<'a, C: Ciphersuite>(
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
    statement: Statement<'a, C>,
    witness: Witness<'a, C>,
) -> Proof<C> {
    transcript.message(STATEMENT_LABEL, &statement.encode());

    let k = <C::Group as Group>::Field::random(rng);
    let big_k = statement.phi(&k);

    transcript.message(
        COMMITMENT_LABEL,
        &encode_point::<C>(&big_k),
    );
    let mut rng = transcript.challenge_then_build_rng(CHALLENGE_LABEL);
    let e = <C::Group as Group>::Field::random(&mut rng);

    let s = k + e * *witness.x;
    Proof { e, s }
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

    let big_k: Element<C> = statement.phi(&proof.s) - *statement.public * proof.e;

    transcript.message(
        COMMITMENT_LABEL,
        &encode_point::<C>(&big_k),
    );
    let mut rng = transcript.challenge_then_build_rng(CHALLENGE_LABEL);
    let e = <C::Group as Group>::Field::random(&mut rng);

    e == proof.e
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
        let witness = Witness { x: &x };

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
