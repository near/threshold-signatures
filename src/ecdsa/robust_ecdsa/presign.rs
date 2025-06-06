use serde::{Deserialize, Serialize};
use rand_core::OsRng;

use crate::{
    compat::CSCurve,
    crypto::polynomials::generate_secret_polynomial,
    participants::ParticipantList,
    protocol::{
        internal::SharedChannel,
        Participant,
        ProtocolError
    },
};

use frost_secp256k1::*;
type C = Secp256K1Sha256;
type Element = <Secp256K1Group as Group>::Element;
type Scalar = <Secp256K1ScalarField as Field>::Scalar;

/// The output of the presigning protocol.
///
/// This output is basically all the parts of the signature that we can perform
/// without knowing the message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignOutput {
    /// The public nonce commitment.
    pub big_r: Element,

    /// Our secret shares of the nonces.
    pub h_i: Scalar,
    pub d_i: Scalar,
    pub e_i: Scalar,
}


fn zero_secret_sharing_2t(
    threshold: usize,
    rng: &mut OsRng,
)-> Vec<Scalar> {
    let secret = Secp256K1ScalarField::zero();
    let threshold = 2 * threshold;
    generate_secret_polynomial::<C>(secret, threshold, rng)
}



async fn do_presign<C: CSCurve>(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
) -> Result<PresignOutput, ProtocolError> {
    unimplemented!("TODO")
}