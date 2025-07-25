use crate::compat::CSCurve;
use crate::ecdsa::triples::{TriplePub, TripleShare};
use crate::ecdsa::KeygenOutput;
use crate::participants::ParticipantCounter;
use crate::protocol::internal::{make_protocol, Comms, SharedChannel};
use crate::protocol::{InitializationError, Protocol};
use crate::{
    participants::ParticipantList,
    protocol::{Participant, ProtocolError},
};
use elliptic_curve::{Field, Group, ScalarPrimitive};
use frost_secp256k1::keys::SigningShare;
use frost_secp256k1::VerifyingKey;
use serde::{Deserialize, Serialize};

/// The output of the presigning protocol.
///
/// This output is basically all the parts of the signature that we can perform
/// without knowing the message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignOutput<C: CSCurve> {
    /// The public nonce commitment.
    pub big_r: C::AffinePoint,
    /// Our share of the nonce value.
    pub k: C::Scalar,
    /// Our share of the sigma value.
    pub sigma: C::Scalar,
}

/// The arguments needed to create a presignature.
#[derive(Debug, Clone)]
pub struct PresignArguments<C: CSCurve> {
    /// The first triple's public information, and our share.
    pub triple0: (TripleShare<C>, TriplePub<C>),
    /// Ditto, for the second triple.
    pub triple1: (TripleShare<C>, TriplePub<C>),
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    /// This is of type KeygenOutput<Secp256K1Sha256> from Frost implementation
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the presignature, which must match the original threshold
    pub threshold: usize,
}

/// Transforms a verification key of type Secp256k1SHA256 to CSCurve of cait-sith
fn from_secp256k1sha256_to_cscurve_vk<C: CSCurve>(
    verifying_key: &VerifyingKey,
) -> Result<C::ProjectivePoint, ProtocolError> {
    // serializes into a canonical byte array buf of length 33 bytes using the  affine point representation
    let bytes = verifying_key
        .serialize()
        .map_err(|_| ProtocolError::PointSerialization)?;

    let bytes: [u8; 33] = bytes.try_into().expect("Slice is not 33 bytes long");
    let point = match C::from_bytes_to_affine(bytes) {
        Some(point) => point,
        _ => return Err(ProtocolError::PointSerialization),
    };
    Ok(point)
}

/// Transforms a secret key of type Secp256k1Sha256 to CSCurve of cait-sith
fn from_secp256k1sha256_to_cscurve_sk<C: CSCurve>(private_share: &SigningShare) -> C::Scalar {
    let bytes = private_share.to_scalar().to_bytes();
    #[allow(clippy::unnecessary_fallible_conversions)]
    let bytes: [u8; 32] = bytes.try_into().expect("Slice is not 32 bytes long");
    C::from_bytes_to_scalar(bytes).unwrap()
}

async fn do_presign<C: CSCurve>(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    bt_participants: ParticipantList,
    bt_id: Participant,
    args: PresignArguments<C>,
) -> Result<PresignOutput<C>, ProtocolError> {
    // Spec 1.2 + 1.3
    let big_k: C::ProjectivePoint = args.triple0.1.big_a.into();

    let big_d = args.triple0.1.big_b;
    let big_kd = args.triple0.1.big_c;

    let big_a: C::ProjectivePoint = args.triple1.1.big_a.into();
    let big_b: C::ProjectivePoint = args.triple1.1.big_b.into();

    let sk_lambda = participants.lagrange::<C>(me);
    let bt_lambda = bt_participants.lagrange::<C>(bt_id);

    let k_i = args.triple0.0.a;
    let k_prime_i = bt_lambda * k_i;
    let kd_i: C::Scalar = bt_lambda * args.triple0.0.c; // if this is zero, then the broadcast kdi is also zero.

    let a_i = args.triple1.0.a;
    let b_i = args.triple1.0.b;
    let c_i = args.triple1.0.c;
    let a_prime_i = bt_lambda * a_i;
    let b_prime_i = bt_lambda * b_i;

    let public_key = from_secp256k1sha256_to_cscurve_vk::<C>(&args.keygen_out.public_key)?;
    let big_x: C::ProjectivePoint = public_key;
    let private_share = from_secp256k1sha256_to_cscurve_sk::<C>(&args.keygen_out.private_share);
    let x_prime_i = sk_lambda * private_share;

    // Spec 1.4
    let wait0 = chan.next_waitpoint();
    {
        let kd_i: ScalarPrimitive<C> = kd_i.into();
        chan.send_many(wait0, &kd_i);
    }

    // Spec 1.9
    let ka_i: C::Scalar = k_prime_i + a_prime_i;
    let xb_i: C::Scalar = x_prime_i + b_prime_i;

    // Spec 1.10
    let wait1 = chan.next_waitpoint();
    {
        let ka_i: ScalarPrimitive<C> = ka_i.into();
        let xb_i: ScalarPrimitive<C> = xb_i.into();
        chan.send_many(wait1, &(ka_i, xb_i));
    }

    // Spec 2.1 and 2.2
    let mut kd = kd_i;
    let mut seen = ParticipantCounter::new(&participants);
    seen.put(me);
    while !seen.full() {
        let (from, kd_j): (_, ScalarPrimitive<C>) = chan.recv(wait0).await?;

        if kd_j.is_zero().into() {
            return Err(ProtocolError::AssertionFailed(
                "Received zero share of kd, indicating a triple wasn't available.".to_string(),
            ));
        }

        if !seen.put(from) {
            continue;
        }
        kd += C::Scalar::from(kd_j);
    }

    // Spec 2.3
    if big_kd != (C::ProjectivePoint::generator() * kd).into() {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }

    // Spec 2.4 and 2.5
    let mut ka = ka_i;
    let mut xb = xb_i;
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, (ka_j, xb_j)): (_, (ScalarPrimitive<C>, ScalarPrimitive<C>)) =
            chan.recv(wait1).await?;
        if !seen.put(from) {
            continue;
        }
        ka += C::Scalar::from(ka_j);
        xb += C::Scalar::from(xb_j);
    }

    // Spec 2.6
    if (C::ProjectivePoint::generator() * ka != big_k + big_a)
        || (C::ProjectivePoint::generator() * xb != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }

    // Spec 2.7
    let kd_inv: Option<C::Scalar> = kd.invert().into();
    let kd_inv =
        kd_inv.ok_or_else(|| ProtocolError::AssertionFailed("failed to invert kd".to_string()))?;
    let big_r = (C::ProjectivePoint::from(big_d) * kd_inv).into();

    // Spec 2.8
    let lambda_diff = bt_lambda * sk_lambda.invert().expect("to invert sk_lambda");
    let sigma_i = ka * private_share - (xb * a_i - c_i) * lambda_diff;

    Ok(PresignOutput {
        big_r,
        k: k_i * lambda_diff,
        sigma: sigma_i,
    })
}

/// The presignature protocol.
///
/// This is the first phase of performing a signature, in which we perform
/// all the work we can do without yet knowing the message to be signed.
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never used.
pub fn presign<C: CSCurve>(
    participants: &[Participant],
    me: Participant,
    bt_participants: &[Participant],
    bt_id: Participant,
    args: PresignArguments<C>,
) -> Result<impl Protocol<Output = PresignOutput<C>>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };
    // Spec 1.1
    if args.threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "threshold must be <= participant count".to_string(),
        ));
    }
    // NOTE: We omit the check that the new participant set was present for
    // the triple generation, because presumably they need to have been present
    // in order to have shares.

    // Also check that we have enough participants to reconstruct shares.
    if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
        return Err(InitializationError::BadParameters(
            "New threshold must match the threshold of both triples".to_string(),
        ));
    }

    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    })?;

    let all_bt_ids = ParticipantList::new(bt_participants).ok_or_else(|| {
        InitializationError::BadParameters(
            "bt_participants list cannot contain duplicates".to_string(),
        )
    })?;

    let ctx = Comms::new();
    let fut = do_presign(
        ctx.shared_channel(),
        participants,
        me,
        all_bt_ids,
        bt_id,
        args,
    );
    Ok(make_protocol(ctx, fut))
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;

    use crate::{ecdsa::math::Polynomial, ecdsa::triples, protocol::run_protocol};
    use frost_secp256k1::keys::{PublicKeyPackage, VerifyingShare};
    use frost_secp256k1::Identifier;
    use std::collections::BTreeMap;

    use k256::{ProjectivePoint, Secp256k1};

    #[test]
    fn test_presign() {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
        ];
        let original_threshold = 2;
        let f = Polynomial::<Secp256k1>::random(&mut OsRng, original_threshold);
        let big_x = ProjectivePoint::GENERATOR * f.evaluate_zero();

        let threshold = 2;

        let (triple0_pub, triple0_shares) =
            triples::deal(&mut OsRng, &participants, original_threshold);
        let (triple1_pub, triple1_shares) =
            triples::deal(&mut OsRng, &participants, original_threshold);

        #[allow(clippy::type_complexity)]
        let mut protocols: Vec<(
            Participant,
            Box<dyn Protocol<Output = PresignOutput<Secp256k1>>>,
        )> = Vec::with_capacity(participants.len());

        for ((p, triple0), triple1) in participants
            .iter()
            .take(3)
            .zip(triple0_shares.into_iter())
            .zip(triple1_shares.into_iter())
        {
            let private_share = f.evaluate(&p.scalar::<Secp256k1>());
            let dummy_tree: BTreeMap<Identifier, VerifyingShare> = BTreeMap::new();
            let verifying_key = VerifyingKey::new(big_x);
            let public_key_package = PublicKeyPackage::new(dummy_tree, verifying_key);
            let keygen_out = KeygenOutput {
                private_share: SigningShare::new(private_share),
                public_key: *public_key_package.verifying_key(),
            };

            let protocol = presign(
                &participants[..3],
                *p,
                &participants[..3],
                *p,
                PresignArguments {
                    triple0: (triple0, triple0_pub.clone()),
                    triple1: (triple1, triple1_pub.clone()),
                    keygen_out,
                    threshold,
                },
            );
            assert!(protocol.is_ok());
            let protocol = protocol.unwrap();
            protocols.push((*p, Box::new(protocol)));
        }

        let result = run_protocol(protocols);
        assert!(result.is_ok());
        let result = result.unwrap();

        assert!(result.len() == 3);
        assert_eq!(result[0].1.big_r, result[1].1.big_r);
        assert_eq!(result[1].1.big_r, result[2].1.big_r);

        let big_k = result[2].1.big_r;

        let participants = vec![result[0].0, result[1].0];
        let k_shares = [result[0].1.k, result[1].1.k];
        let sigma_shares = [result[0].1.sigma, result[1].1.sigma];
        let p_list = ParticipantList::new(&participants).unwrap();
        let k = p_list.lagrange::<Secp256k1>(participants[0]) * k_shares[0]
            + p_list.lagrange::<Secp256k1>(participants[1]) * k_shares[1];
        assert_eq!(ProjectivePoint::GENERATOR * k.invert().unwrap(), big_k);
        let sigma = p_list.lagrange::<Secp256k1>(participants[0]) * sigma_shares[0]
            + p_list.lagrange::<Secp256k1>(participants[1]) * sigma_shares[1];
        assert_eq!(sigma, k * f.evaluate_zero());
    }
}
