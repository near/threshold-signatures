use crate::compat::CSCurve;
use crate::{
    participants::ParticipantList,
    protocol::{
        internal::SharedChannel,
        Participant,
        ProtocolError
    },
};
use serde::{Deserialize, Serialize};

/// The output of the presigning protocol.
///
/// This output is basically all the parts of the signature that we can perform
/// without knowing the message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignOutput<C: CSCurve> {
    /// The public nonce commitment.
    pub big_r: C::AffinePoint,
    /// Our share of the nonces value.
    pub h_i: C::Scalar,
    pub d_i: C::Scalar,
    pub e_i: C::Scalar,
}



async fn do_presign<C: CSCurve>(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
) -> Result<PresignOutput<C>, ProtocolError> {
    todo!("TODO")
}