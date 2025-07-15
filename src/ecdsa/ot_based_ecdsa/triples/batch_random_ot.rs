use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConditionallySelectable;

use crate::{
    ecdsa::{
        Field,
        ProjectivePoint,
        Secp256K1ScalarField,
        VerifyingKey,
    },
    protocol::{
        internal::{make_protocol, Comms, PrivateChannel},
        run_two_party_protocol, Participant, ProtocolError,
    },
};

use super::constants::SECURITY_PARAMETER;
use super::bits::{BitMatrix, BitVector, SquareBitMatrix, SEC_PARAM_8};

const BATCH_RANDOM_OT_HASH: &[u8] = b"Near threshold signatures batch ROT";

fn hash(
    i: usize,
    big_x_i: &VerifyingKey,
    big_y: &VerifyingKey,
    p: &VerifyingKey,
) -> Result<BitVector, ProtocolError> {
    let mut hasher = Sha256::new();
    hasher.update(BATCH_RANDOM_OT_HASH);
    hasher.update(&(i as u64).to_le_bytes());
    hasher.update(&big_x_i.serialize()?);
    hasher.update(&big_y.serialize()?);
    hasher.update(&p.serialize()?);

    let bytes: [u8; 32] = hasher.finalize().into();
    // the hash output is 256 bits
    // it is possible to take the first 128 bits out
    let bytes: [u8; SEC_PARAM_8] = bytes[0..SEC_PARAM_8].try_into().unwrap();

    Ok(BitVector::from_bytes(&bytes))
}

type BatchRandomOTOutputSender = (SquareBitMatrix, SquareBitMatrix);

pub async fn batch_random_ot_sender(
    mut chan: PrivateChannel,
) -> Result<BatchRandomOTOutputSender, ProtocolError> {
    // Spec 1
    let y = Secp256K1ScalarField::random(&mut OsRng);
    let big_y = ProjectivePoint::GENERATOR * y;
    let big_z = big_y * y;

    // One way to be able to serialize and send big_y a verifying key out of it
    // as it contains a private struct SerializableElement
    let ser_big_y = VerifyingKey::new(big_y);
    let wait0 = chan.next_waitpoint();
    chan.send(wait0, &ser_big_y);

    let tasks = (0..SECURITY_PARAMETER).map(|i| {
        let mut chan = chan.child(i as u64);
        async move {
            let wait0 = chan.next_waitpoint();
            let ser_big_x_i: VerifyingKey = chan.recv(wait0).await?;

            let y_big_x_i = ser_big_x_i.to_element() * y;

            let big_k0 = hash(i, &ser_big_x_i, &ser_big_y, &VerifyingKey::new(y_big_x_i))?;
            let big_k1 = hash(i, &ser_big_x_i, &ser_big_y, &VerifyingKey::new(y_big_x_i - big_z))?;

            Ok::<_, ProtocolError>((big_k0, big_k1))
        }
    });
    let out: Vec<(BitVector, BitVector)> = futures::future::try_join_all(tasks).await?;

    let big_k0: BitMatrix = out.iter().map(|r| r.0).collect();
    let big_k1: BitMatrix = out.iter().map(|r| r.1).collect();
    Ok((big_k0.try_into().unwrap(), big_k1.try_into().unwrap()))
}

pub async fn batch_random_ot_sender_many<const N: usize>(
    mut chan: PrivateChannel,
) -> Result<Vec<BatchRandomOTOutputSender>, ProtocolError> {
    assert!(N > 0);
    let mut big_y_v = vec![];
    let mut big_z_v = vec![];
    let mut yv = vec![];
    for _ in 0..N {
        // Spec 1
        let y = Secp256K1ScalarField::random(&mut OsRng);
        let big_y = ProjectivePoint::GENERATOR * y;
        let big_z = big_y * y;
        yv.push(y);
        big_y_v.push(big_y);
        big_z_v.push(big_z);
    }

    let wait0 = chan.next_waitpoint();
    let mut big_y_ser_v = vec![];
    for i in 0..N {
        let big_y_verkey = VerifyingKey::new(big_y_v[i]);
        big_y_ser_v.push(big_y_verkey);
    }
    chan.send(wait0, &big_y_ser_v);

    let y_v_arc = Arc::new(yv);
    let big_y_verkey_v_arc = Arc::new(big_y_ser_v);
    let big_z_v_arc = Arc::new(big_z_v);
    let tasks = (0..SECURITY_PARAMETER).map(|i| {
        let yv_arc = y_v_arc.clone();
        let big_y_verkey_v_arc = big_y_verkey_v_arc.clone();
        let big_z_v_arc = big_z_v_arc.clone();
        let mut chan = chan.child(i as u64);
        async move {
            let wait0 = chan.next_waitpoint();
            let big_x_i_verkey_v: Vec<VerifyingKey> = chan.recv(wait0).await?;

            let mut ret = vec![];
            for j in 0..N {
                let y = &yv_arc.as_slice()[j];
                let big_y_verkey = &big_y_verkey_v_arc.as_slice()[j];
                let big_z = &big_z_v_arc.as_slice()[j];
                let y_big_x_i = big_x_i_verkey_v[j].to_element() * *y;
                let big_k0 = hash(i, &big_x_i_verkey_v[j], big_y_verkey, &VerifyingKey::new(y_big_x_i));
                let big_k1 = hash(i, &big_x_i_verkey_v[j], big_y_verkey, &VerifyingKey::new(y_big_x_i - big_z));
                ret.push((big_k0, big_k1));
            }

            Ok::<_, ProtocolError>(ret)
        }
    });
    let outs: Vec<Vec<(BitVector, BitVector)>> = futures::future::try_join_all(tasks).await?;
    // batch dimension is on the inside but needs to be on the outside
    let mut reshaped_outs: Vec<Vec<_>> = Vec::new();
    for _ in 0..N {
        reshaped_outs.push(Vec::new());
    }
    for i in 0..outs.len() {
        for j in 0..N {
            reshaped_outs[j].push(outs[i][j])
        }
    }
    let outs = reshaped_outs;
    let mut ret = vec![];
    for i in 0..N {
        let out = &outs[i];
        let big_k0: BitMatrix = out.iter().map(|r| r.0).collect();
        let big_k1: BitMatrix = out.iter().map(|r| r.1).collect();
        ret.push((big_k0.try_into().unwrap(), big_k1.try_into().unwrap()));
    }

    Ok(ret)
}

type BatchRandomOTOutputReceiver = (BitVector, SquareBitMatrix);

pub async fn batch_random_ot_receiver(
    mut chan: PrivateChannel,
) -> Result<BatchRandomOTOutputReceiver, ProtocolError> {
    // Step 3
    let wait0 = chan.next_waitpoint();
    // deserialization prevents receiving the identity
    let big_y_verkey: VerifyingKey = chan.recv(wait0).await?;
    let big_y = big_y_verkey.to_element();
    let delta = BitVector::random(&mut OsRng);

    let out = delta
        .bits()
        .enumerate()
        .map(|(i, d_i)| {
            let mut chan = chan.child(i as u64);
            // Step 4
            let x_i = Secp256K1ScalarField::random(&mut OsRng);
            let mut big_x_i = ProjectivePoint::GENERATOR * x_i;
            big_x_i.conditional_assign(&(big_x_i + big_y), d_i);

            // Step 6
            let wait0 = chan.next_waitpoint();
            let big_x_i_verkey = VerifyingKey::new(big_x_i);
            chan.send(wait0, &big_x_i_verkey);

            // Step 5
            hash(i, &big_x_i_verkey, &big_y_verkey, &VerifyingKey::new(big_y * x_i))
        })
        .collect::<Vec<_>>();
    let big_k: BitMatrix = out.into_iter().collect();
    Ok((delta, big_k.try_into().unwrap()))
}

pub async fn batch_random_ot_receiver_many<const N: usize>(
    mut chan: PrivateChannel,
) -> Result<Vec<BatchRandomOTOutputReceiver>, ProtocolError> {
    assert!(N > 0);
    // Step 3
    let wait0 = chan.next_waitpoint();
    // deserialization prevents receiving the identity
    let big_y_verkey_v: Vec<VerifyingKey> = chan.recv(wait0).await?;

    let mut big_y_v = vec![];
    let mut deltav = vec![];
    for i in 0..N {
        let big_y_verkey = big_y_verkey_v[i];
        let big_y = big_y_verkey.to_element();
        let delta = BitVector::random(&mut OsRng);
        big_y_v.push(big_y);
        deltav.push(delta);
    }

    let big_y_v_arc = Arc::new(big_y_v);
    let big_y_verkey_v_arc = Arc::new(big_y_verkey_v);

    // inner is batch, outer is bits
    let mut choices: Vec<Vec<_>> = Vec::new();
    for _ in deltav[0].bits() {
        choices.push(Vec::new());
    }
    for j in 0..N {
        for (i, d_i) in deltav[j].bits().enumerate() {
            choices[i].push(d_i);
        }
    }
    // wrap in arc
    let choices: Vec<_> = choices.into_iter().map(Arc::new).collect();

    let mut outs = Vec::new();
    for i in 0..choices.len() {
        let mut chan = chan.child(i as u64);
        // clone arcs
        let d_i_v = choices[i].clone();
        let big_y_v_arc = big_y_v_arc.clone();
        let big_y_verkey_v_arc = big_y_verkey_v_arc.clone();
        let hashv = {
            let mut x_i_v = Vec::new();
            let mut big_x_i_v = Vec::new();
            for j in 0..N {
                let d_i = d_i_v[j];
                // Step 4
                let x_i = Secp256K1ScalarField::random(&mut OsRng);
                let mut big_x_i = ProjectivePoint::GENERATOR * x_i;
                big_x_i.conditional_assign(&(big_x_i + big_y_v_arc[j]), d_i);
                x_i_v.push(x_i);
                big_x_i_v.push(big_x_i);
            }
            // Step 6
            let wait0 = chan.next_waitpoint();

            let mut big_x_i_verkey_v = Vec::new();
            for j in 0..N {
                let big_x_i_verkey = VerifyingKey::new(big_x_i_v[j]);
                big_x_i_verkey_v.push(big_x_i_verkey);
            }
            chan.send(wait0, &big_x_i_verkey_v);

            // Step 5
            let mut hashv = Vec::new();
            for j in 0..N {
                let big_x_i_verkey = big_x_i_verkey_v[j];
                let big_y_verkey = big_y_verkey_v_arc[j];
                let big_y = big_y_v_arc[j];
                let x_i = x_i_v[j];
                hashv.push(hash(i, &big_x_i_verkey, &big_y_verkey, &VerifyingKey::new(big_y * x_i)));
            }
            hashv
        };
        outs.push(hashv)
    }

    // batch dimension is on the inside but needs to be on the outside
    let mut reshaped_outs: Vec<Vec<_>> = Vec::new();
    for _ in 0..N {
        reshaped_outs.push(Vec::new());
    }
    for i in 0..outs.len() {
        for j in 0..N {
            reshaped_outs[j].push(outs[i][j]);
        }
    }
    let outs = reshaped_outs;
    let mut ret = Vec::new();
    for j in 0..N {
        let delta = deltav[j];
        let out = &outs[j];
        let big_k: BitMatrix = out.iter().cloned().collect();
        let h = SquareBitMatrix::try_from(big_k);
        ret.push((delta, h.unwrap()))
    }
    Ok(ret)
}

/// Run the batch random OT protocol between two parties.
#[allow(dead_code)]
pub(crate) fn run_batch_random_ot(
) -> Result<(BatchRandomOTOutputSender, BatchRandomOTOutputReceiver), ProtocolError> {
    let s = Participant::from(0u32);
    let r = Participant::from(1u32);
    let comms_s = Comms::new();
    let comms_r = Comms::new();

    run_two_party_protocol(
        s,
        r,
        &mut make_protocol(
            comms_s.clone(),
            batch_random_ot_sender(comms_s.private_channel(s, r)),
        ),
        &mut make_protocol(
            comms_r.clone(),
            batch_random_ot_receiver(comms_r.private_channel(r, s)),
        ),
    )
}

/// Run the batch random OT many protocol between two parties.
#[allow(dead_code)]
pub(crate) fn run_batch_random_ot_many<const N: usize>() -> Result<
    (
        Vec<BatchRandomOTOutputSender>,
        Vec<BatchRandomOTOutputReceiver>,
    ),
    ProtocolError,
> {
    let s = Participant::from(0u32);
    let r = Participant::from(1u32);
    let comms_s = Comms::new();
    let comms_r = Comms::new();

    run_two_party_protocol(
        s,
        r,
        &mut make_protocol(
            comms_s.clone(),
            batch_random_ot_sender_many::<N>(comms_s.private_channel(s, r)),
        ),
        &mut make_protocol(
            comms_r.clone(),
            batch_random_ot_receiver_many::<N>(comms_r.private_channel(r, s)),
        ),
    )
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_batch_random_ot() {
        let res = run_batch_random_ot();
        assert!(res.is_ok());
        let ((k0, k1), (delta, k_delta)) = res.unwrap();

        // Check that we've gotten the right rows of the two matrices.
        for (((row0, row1), delta_i), row_delta) in k0
            .matrix
            .rows()
            .zip(k1.matrix.rows())
            .zip(delta.bits())
            .zip(k_delta.matrix.rows())
        {
            assert_eq!(
                BitVector::conditional_select(row0, row1, delta_i),
                *row_delta
            );
        }
    }

    #[test]
    fn test_batch_random_ot_many() {
        const N: usize = 10;
        let res = run_batch_random_ot_many::<N>();
        assert!(res.is_ok());
        let (a, b) = res.unwrap();
        for i in 0..N {
            let ((k0, k1), (delta, k_delta)) = (&a[i], &b[i]);
            // Check that we've gotten the right rows of the two matrices.
            for (((row0, row1), delta_i), row_delta) in k0
                .matrix
                .rows()
                .zip(k1.matrix.rows())
                .zip(delta.bits())
                .zip(k_delta.matrix.rows())
            {
                assert_eq!(
                    BitVector::conditional_select(row0, row1, delta_i),
                    *row_delta
                );
            }
        }
    }
}
