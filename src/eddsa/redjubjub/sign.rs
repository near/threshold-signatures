use reddsa::SigType;

use super::{KeygenOutput, SignatureOption};
use crate::errors::{InitializationError, ProtocolError};
use crate::participants::{Participant, ParticipantList};
use crate::protocol::helpers::recv_from_others;
use crate::protocol::internal::{make_protocol, Comms, SharedChannel};
use crate::protocol::Protocol;

use frost_ed25519::keys::{KeyPackage, PublicKeyPackage, SigningShare};
use frost_ed25519::{aggregate, rand_core, round1, round2, VerifyingKey};
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use reddsa::SigningKey;

/// Returns a future that executes signature protocol for *the Coordinator*.
///
/// WARNING: Extracted from FROST documentation:
/// In all of the main FROST ciphersuites, the entire message must be sent
/// to participants. In some cases, where the message is too big, it may be
/// necessary to send a hash of the message instead. We strongly suggest
/// creating a specific ciphersuite for this, and not just sending the hash
/// as if it were the message.
/// For reference, see how RFC 8032 handles "pre-hashing".
async fn do_sign_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    threshold: usize,
    me: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    rng: &mut impl CryptoRngCore,
) -> Result<SignatureOption, ProtocolError> {

    unimplemented!()
}