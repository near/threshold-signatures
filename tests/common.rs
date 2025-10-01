use std::collections::HashMap;

use rand_core::OsRng;

use threshold_signatures::{
    self, keygen,
    protocol::{run_protocol, Participant, Protocol},
    Ciphersuite, KeygenOutput,
};

type GenProtocol<C> = Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput<C>>>)>;

pub fn generate_participants(number: usize) -> Vec<Participant> {
    (0..number)
        .map(|i| Participant::from(i as u32))
        .collect::<Vec<_>>()
}

#[allow(clippy::missing_panics_doc)]
pub fn run_keygen<C: Ciphersuite>(
    participants: &[Participant],
    threshold: usize,
) -> HashMap<Participant, KeygenOutput<C>>
where <<C as threshold_signatures::frost_core::Ciphersuite>::Group as threshold_signatures::frost_core::Group>::Element: std::marker::Send
, <<<C as threshold_signatures::frost_core::Ciphersuite>::Group as threshold_signatures::frost_core::Group>::Field as threshold_signatures::frost_core::Field>::Scalar: std::marker::Send
{
    let mut protocols: GenProtocol<C> = Vec::with_capacity(participants.len());

    for p in participants {
        let protocol = keygen::<C>(participants, *p, threshold, OsRng).unwrap();
        protocols.push((*p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap().into_iter().collect()
}
