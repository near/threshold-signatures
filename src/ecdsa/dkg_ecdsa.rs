#[cfg(test)]
mod test {
    use frost_secp256k1::{Group, Secp256K1Group, Secp256K1Sha256};
    type E = Secp256K1Sha256;

    use crate::participants::ParticipantList;
    use crate::protocol::Participant;
    use crate::test::{
        assert_public_key_invariant, generate_participants, run_keygen, run_refresh, run_reshare,
    };
    use crate::threshold::Scheme;
    use frost_core::{Ciphersuite, Field};
    use std::error::Error;

    #[test]
    fn test_keygen() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(31u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let threshold = 2;

        let result = run_keygen::<E>(Scheme::Dkg, &participants, threshold)?;
        assert!(result.len() == participants.len());
        assert_public_key_invariant(&result);

        let pub_key = result[2].1.public_key.to_element();

        let p_list = ParticipantList::new(&participants).unwrap();
        let mut x = <<E as Ciphersuite>::Group as Group>::Field::zero();
        for (p, key) in &result {
            x += p_list.lagrange::<E>(*p)? * key.private_share.to_scalar();
        }
        assert_eq!(<Secp256K1Group>::generator() * x, pub_key);
        Ok(())
    }

    #[test]
    fn test_refresh() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(31u32),
            Participant::from(2u32),
        ];
        let threshold = 2;

        let result0 = run_keygen::<E>(Scheme::Dkg, &participants, threshold)?;
        assert_public_key_invariant(&result0);

        let pub_key = result0[2].1.public_key.to_element();

        let result1 = run_refresh(Scheme::Dkg, &participants, result0, threshold)?;
        assert_public_key_invariant(&result1);

        let p_list = ParticipantList::new(&participants).unwrap();
        let mut x = <<E as Ciphersuite>::Group as Group>::Field::zero();
        for (p, key) in &result1 {
            x += p_list.lagrange::<E>(*p)? * key.private_share.to_scalar();
        }
        assert_eq!(<Secp256K1Group>::generator() * x, pub_key);
        Ok(())
    }

    #[test]
    fn test_reshare() -> Result<(), Box<dyn Error>> {
        let participants = generate_participants(3);
        let threshold0 = 2;
        let threshold1 = 3;

        let result0 = run_keygen::<E>(Scheme::Dkg, &participants, threshold0)?;
        assert_public_key_invariant(&result0);

        let pub_key = result0[2].1.public_key;

        let mut new_participants = participants.clone();
        new_participants.push(Participant::from(3u32));
        new_participants.push(Participant::from(4u32));
        new_participants.push(Participant::from(5u32)); // Total N=6

        let result1 = run_reshare(
            Scheme::Dkg,
            &participants,
            &pub_key,
            result0,
            threshold0,
            threshold1,
            new_participants.clone(),
        )?;
        assert_public_key_invariant(&result1);

        let p_list = ParticipantList::new(&new_participants).unwrap();
        let mut x = <<E as Ciphersuite>::Group as Group>::Field::zero();
        for (p, key) in &result1 {
            x += p_list.lagrange::<E>(*p)? * key.private_share.to_scalar();
        }

        assert_eq!(<Secp256K1Group>::generator() * x, pub_key.to_element());

        Ok(())
    }
}
