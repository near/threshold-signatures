use crate::protocol::MessageData;
use crate::participants::Participant;
use crate::test_utils::snapshot::ProtocolSnapshot;

pub struct Simulator {
  /// the real_participant we are simulating for
  real_participant: Participant,
  /// the real_participant view to deliver
  view: Vec<(Participant, MessageData)>,
  /// number of simulated participants
  simulated_participants: usize,
}

impl Simulator {
  pub fn new(real_participant: Participant, protocol_snap: ProtocolSnapshot) -> Option<Self>{
    let simulated_participants = protocol_snap.number_of_participants() - 1;
    if simulated_participants <= 0 {
      return None
    }
    protocol_snap
      .get_received_messages(&real_participant)
      .map(|view| Self{real_participant, view, simulated_participants})
  }

  pub fn real_participant(&self) -> Participant{
    self.real_participant
  }

  pub fn get_recorded_messages(self) -> Vec<(Participant, MessageData)>{
    self.view
  }

  // pub fn receive_many(&self, to: Participant, message: MessageData){


  // }

  // pub fn receive_private(&self, to: Participant, message: MessageData){

  // }

}