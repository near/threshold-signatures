use crate::{
    compat::CSCurve,
    constants::SECURITY_PARAMETER,
    crypto::HashOutput,
    participants::ParticipantList,
    protocol::{internal::PrivateChannel, Participant, ProtocolError},
};
use std::sync::Arc;

use super::{
    batch_random_ot::{batch_random_ot_receiver, batch_random_ot_sender},
    mta::{mta_receiver, mta_sender},
    random_ot_extension::{
        random_ot_extension_receiver, random_ot_extension_sender, RandomOtExtensionParams,
    },
};
use crate::protocol::internal::Comms;
use std::collections::VecDeque;

pub async fn multiplication_sender<C: CSCurve>(
    chan: PrivateChannel,
    sid: &[u8],
    a_i: &C::Scalar,
    b_i: &C::Scalar,
) -> Result<C::Scalar, ProtocolError> {
    // First, run a fresh batch random OT ourselves
    let (delta, k) = batch_random_ot_receiver::<C>(chan.child(0)).await?;

    let batch_size = C::BITS + SECURITY_PARAMETER;
    // Step 1
    let mut res0 = random_ot_extension_sender::<C>(
        chan.child(1),
        RandomOtExtensionParams {
            sid,
            batch_size: 2 * batch_size,
        },
        delta,
        &k,
    )
    .await?;
    let res1 = res0.split_off(batch_size);

    // Step 2
    let task0 = mta_sender::<C>(chan.child(2), res0, *a_i);
    let task1 = mta_sender::<C>(chan.child(3), res1, *b_i);

    // Step 3
    let (gamma0, gamma1) = futures::future::join(task0, task1).await;

    Ok(gamma0? + gamma1?)
}

pub async fn multiplication_receiver<C: CSCurve>(
    chan: PrivateChannel,
    sid: &[u8],
    a_i: &C::Scalar,
    b_i: &C::Scalar,
) -> Result<C::Scalar, ProtocolError> {
    // First, run a fresh batch random OT ourselves
    let (k0, k1) = batch_random_ot_sender::<C>(chan.child(0)).await?;

    let batch_size = C::BITS + SECURITY_PARAMETER;
    // Step 1
    let mut res0 = random_ot_extension_receiver::<C>(
        chan.child(1),
        RandomOtExtensionParams {
            sid,
            batch_size: 2 * batch_size,
        },
        &k0,
        &k1,
    )
    .await?;
    let res1 = res0.split_off(batch_size);

    // Step 2
    let task0 = mta_receiver::<C>(chan.child(2), res0, *b_i);
    let task1 = mta_receiver::<C>(chan.child(3), res1, *a_i);

    // Step 3
    let (gamma0, gamma1) = futures::future::join(task0, task1).await;

    Ok(gamma0? + gamma1?)
}

pub async fn multiplication<C: CSCurve>(
    comms: Comms,
    sid: HashOutput,
    participants: ParticipantList,
    me: Participant,
    a_i: C::Scalar,
    b_i: C::Scalar,
) -> Result<C::Scalar, ProtocolError> {
    let mut tasks = Vec::with_capacity(participants.len() - 1);
    for p in participants.others(me) {
        let fut = {
            let chan = comms.private_channel(me, p);
            async move {
                if p < me {
                    multiplication_sender::<C>(chan, sid.as_ref(), &a_i, &b_i).await
                } else {
                    multiplication_receiver::<C>(chan, sid.as_ref(), &a_i, &b_i).await
                }
            }
        };
        tasks.push(fut);
    }
    let mut out = a_i * b_i;
    for result in futures::future::try_join_all(tasks).await? {
        out += result;
    }
    Ok(out)
}

pub async fn multiplication_many<C: CSCurve, const N: usize>(
    comms: Comms,
    sid: Vec<HashOutput>,
    participants: ParticipantList,
    me: Participant,
    av_iv: Vec<C::Scalar>,
    bv_iv: Vec<C::Scalar>,
) -> Result<Vec<C::Scalar>, ProtocolError> {
    assert!(N > 0);
    let sid_arc = Arc::new(sid);
    let av_iv_arc = Arc::new(av_iv);
    let bv_iv_arc = Arc::new(bv_iv);
    let mut tasks = Vec::with_capacity(participants.len() - 1);
    for i in 0..N {
        let order_key_me = crate::crypto::hash(&(i, me));
        for p in participants.others(me) {
            let sid_arc = sid_arc.clone();
            let av_iv_arc = av_iv_arc.clone();
            let bv_iv_arc = bv_iv_arc.clone();
            let fut = {
                let chan = comms.private_channel(me, p).child(i as u64);
                let order_key_other = crate::crypto::hash(&(i, p));

                async move {
                    // Use a deterministic but random comparison function to decide who
                    // is the sender and who is the receiver. This allows the batched
                    // multiplication operation to put even networking load between the
                    // participants.
                    if order_key_other.as_ref() < order_key_me.as_ref() {
                        multiplication_sender::<C>(
                            chan,
                            sid_arc[i].as_ref(),
                            &av_iv_arc[i],
                            &bv_iv_arc[i],
                        )
                        .await
                    } else {
                        multiplication_receiver::<C>(
                            chan,
                            sid_arc[i].as_ref(),
                            &av_iv_arc[i],
                            &bv_iv_arc[i],
                        )
                        .await
                    }
                }
            };
            tasks.push(fut);
        }
    }
    let mut outs = vec![];
    for i in 0..N {
        let av_i = &av_iv_arc.as_slice()[i];
        let bv_i = &bv_iv_arc.as_slice()[i];
        let out = *av_i * *bv_i;
        outs.push(out);
    }

    let mut results = futures::future::try_join_all(tasks)
        .await?
        .into_iter()
        .collect::<VecDeque<_>>();

    for oi in outs.iter_mut().take(N) {
        for _ in participants.others(me) {
            let result = results.pop_front().unwrap();
            *oi += result;
        }
    }

    Ok(outs)
}

#[cfg(test)]
mod test {
    use k256::{Scalar, Secp256k1};
    use rand_core::OsRng;

    use crate::{
        crypto::hash,
        participants::ParticipantList,
        protocol::{internal::make_protocol, run_protocol, Participant, Protocol, ProtocolError},
    };

    use super::multiplication;
    use crate::ecdsa::triples::multiplication::multiplication_many;
    use crate::protocol::internal::Comms;

    #[test]
    fn test_multiplication() -> Result<(), ProtocolError> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];

        let prep: Vec<_> = participants
            .iter()
            .map(|p| {
                let a_i = Scalar::generate_biased(&mut OsRng);
                let b_i = Scalar::generate_biased(&mut OsRng);
                (p, a_i, b_i)
            })
            .collect();
        let a = prep.iter().fold(Scalar::ZERO, |acc, (_, a_i, _)| acc + a_i);
        let b = prep.iter().fold(Scalar::ZERO, |acc, (_, _, b_i)| acc + b_i);

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = Scalar>>)> =
            Vec::with_capacity(prep.len());

        let sid = hash(b"sid");

        for (p, a_i, b_i) in prep {
            let ctx = Comms::new();
            let prot = make_protocol(
                ctx.clone(),
                multiplication::<Secp256k1>(
                    ctx,
                    sid,
                    ParticipantList::new(&participants).unwrap(),
                    *p,
                    a_i,
                    b_i,
                ),
            );
            protocols.push((*p, Box::new(prot)))
        }

        let result = run_protocol(protocols)?;
        let c = result
            .into_iter()
            .fold(Scalar::ZERO, |acc, (_, c_i)| acc + c_i);

        assert_eq!(a * b, c);

        Ok(())
    }

    #[test]
    fn test_multiplication_many() -> Result<(), ProtocolError> {
        const N: usize = 4;
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];

        let prep: Vec<_> = participants
            .iter()
            .map(|p| {
                let a_iv = (0..N)
                    .map(|_| Scalar::generate_biased(&mut OsRng))
                    .collect::<Vec<_>>();
                let b_iv = (0..N)
                    .map(|_| Scalar::generate_biased(&mut OsRng))
                    .collect::<Vec<_>>();
                (p, a_iv, b_iv)
            })
            .collect();

        let a_v = prep
            .iter()
            .fold(vec![Scalar::ZERO; N], |acc, (_, a_iv, _)| {
                acc.iter()
                    .zip(a_iv.iter())
                    .map(|(acc_i, a_i)| acc_i + a_i)
                    .collect()
            });
        let b_v = prep
            .iter()
            .fold(vec![Scalar::ZERO; N], |acc, (_, _, b_iv)| {
                acc.iter()
                    .zip(b_iv.iter())
                    .map(|(acc_i, b_i)| acc_i + b_i)
                    .collect()
            });

        #[allow(clippy::type_complexity)]
        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = Vec<Scalar>>>)> =
            Vec::with_capacity(prep.len());

        let sids: Vec<_> = (0..N).map(|i| hash(&format!("sid{i}"))).collect();

        for (p, a_iv, b_iv) in prep {
            let ctx = Comms::new();
            let prot = make_protocol(
                ctx.clone(),
                multiplication_many::<Secp256k1, N>(
                    ctx,
                    sids.clone(),
                    ParticipantList::new(&participants).unwrap(),
                    *p,
                    a_iv,
                    b_iv,
                ),
            );
            protocols.push((*p, Box::new(prot)))
        }

        let result = run_protocol(protocols)?;
        let c_v: Vec<_> = result
            .into_iter()
            .fold(vec![Scalar::ZERO; N], |acc, (_, c_iv)| {
                acc.iter()
                    .zip(c_iv.iter())
                    .map(|(acc_i, c_i)| acc_i + c_i)
                    .collect()
            });

        for i in 0..N {
            assert_eq!(a_v[i] * b_v[i], c_v[i]);
        }
        Ok(())
    }
}
