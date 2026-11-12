use std::{
    error::Error,
    fmt,
    path::Path,
    thread,
    time::{Duration, Instant},
};

use clap::Subcommand;
use flux::{
    spine::SpineAdapter,
    tile::Tile,
    timing::InternalMessage,
    utils::{
        directories::{local_share_dir, shmem_dir_queues_with_base},
        short_typename,
    },
};
use silver_common::{
    APP_NAME, ClusterAdminCommand, ClusterAdminRequest, ClusterAdminResponse, ClusterAdminResult,
    ClusterMembers, Enr, MemberAddress, MembershipOperation, SilverSpine,
};

/// Covers a leader that is busy, not one that is gone.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Membership changes go to the leader; run them on its host.
#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum ClusterCommand {
    /// Adds a cluster learner, dialled at the QUIC address of its ENR.
    Add { node_id: u64, enr: Enr },
    /// Makes a caught-up cluster learner a voter.
    Promote { node_id: u64 },
    /// Swaps cluster voter `old` for the caught-up learner `new` in one joint
    /// change.
    Replace { old: u64, new: u64 },
    /// Removes a cluster voter or learner. The leader cannot remove itself.
    Remove { node_id: u64 },
    /// Hands cluster leadership to another voter.
    TransferLeader { node_id: u64 },
    /// Lists the cluster members as the local node sees them.
    Members,
}

impl ClusterCommand {
    /// Prints the outcome; an error means the node refused or never answered.
    pub fn run(self) -> Result<(), Box<dyn Error>> {
        let command = self.admin_command()?;
        let request = ClusterAdminRequest { request_id: rand::random(), command };
        match ClusterAdminClient::attach(&local_share_dir())?.request(request)? {
            ClusterAdminResult::Proposed => {
                println!(
                    "proposed {command:?}; it applies once it commits, check `silver members`"
                );
                Ok(())
            }
            ClusterAdminResult::Members(members) => {
                print!("{}", MembersTable(&members));
                Ok(())
            }
            ClusterAdminResult::Refused(error) => Err(error.into()),
        }
    }

    fn admin_command(self) -> Result<ClusterAdminCommand, String> {
        let operation = match self {
            Self::Add { node_id, enr } => {
                let address = MemberAddress::from_enr(&enr)
                    .ok_or_else(|| format!("the ENR of node {node_id} has no QUIC address"))?;
                MembershipOperation::Add { node_id, address }
            }
            Self::Promote { node_id } => MembershipOperation::Promote { node_id },
            Self::Replace { old, new } => MembershipOperation::Replace { old, new },
            Self::Remove { node_id } => MembershipOperation::Remove { node_id },
            Self::TransferLeader { node_id } => {
                return Ok(ClusterAdminCommand::TransferLeader { node_id });
            }
            Self::Members => return Ok(ClusterAdminCommand::Members),
        };
        Ok(ClusterAdminCommand::Change(operation))
    }
}

struct ClusterAdminClient {
    tile: ResponseTile,
    adapter: SpineAdapter<SilverSpine>,
}

impl ClusterAdminClient {
    /// Opening the spine creates any queue that is missing, so a node that
    /// never ran here is detected first.
    fn attach(base_dir: &Path) -> Result<Self, Box<dyn Error>> {
        let queues = shmem_dir_queues_with_base(base_dir, APP_NAME);
        let queue = short_typename::<InternalMessage<ClusterAdminRequest>>();
        if !queues.join(queue.as_str()).exists() {
            return Err(format!(
                "no silver node with cluster admin support has run with queues in {}",
                queues.display()
            )
            .into());
        }
        let tile = ResponseTile::default();
        let mut spine = SilverSpine::new_with_base_dir(base_dir, None);
        let mut adapter = SpineAdapter::connect_tile(&tile, &mut spine);
        // A consumer attaches at its first read, so an answer sent before
        // then would be missed.
        adapter.subscribe_broadcast::<ClusterAdminResponse>();
        Ok(Self { tile, adapter })
    }

    fn request(
        &mut self,
        request: ClusterAdminRequest,
    ) -> Result<ClusterAdminResult, Box<dyn Error>> {
        self.tile.request_id = request.request_id;
        self.adapter.produce(request);
        let deadline = Instant::now() + RESPONSE_TIMEOUT;
        while Instant::now() < deadline {
            self.tile.loop_body(&mut self.adapter);
            if let Some(result) = self.tile.result.take() {
                return Ok(result);
            }
            thread::sleep(POLL_INTERVAL);
        }
        Err(format!(
            "no answer within {RESPONSE_TIMEOUT:?}: the node is not running, or runs a build \
             without cluster admin support"
        )
        .into())
    }
}

#[derive(Default)]
struct ResponseTile {
    request_id: u64,
    result: Option<ClusterAdminResult>,
}

impl Tile<SilverSpine> for ResponseTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        adapter.consume(|response: ClusterAdminResponse, _| {
            if response.request_id == self.request_id {
                self.result = Some(response.result);
            }
        });
    }
}

struct MembersTable<'a>(&'a ClusterMembers);

impl fmt::Display for MembersTable<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let members = self.0;
        let leading = members.leader_id == Some(members.node_id);
        match members.leader_id {
            Some(leader) => writeln!(f, "node {}, leader {leader}", members.node_id)?,
            None => writeln!(f, "node {}, no known leader", members.node_id)?,
        }
        match members.highest_node_id.checked_add(1) {
            Some(next) => writeln!(f, "commit {}, next free node id {next}", members.commit)?,
            None => writeln!(f, "commit {}, no free node id left", members.commit)?,
        }
        if !leading {
            writeln!(f, "progress is known only on the leader")?;
        }
        writeln!(
            f,
            "{:<6} {:<8} {:<24} {:<10} {:>10} {:>13}",
            "node", "role", "address", "caught up", "match", "last contact"
        )?;
        for row in members.members.iter() {
            let node =
                match (row.node_id == members.node_id, members.leader_id == Some(row.node_id)) {
                    (true, true) => format!("{}*L", row.node_id),
                    (true, false) => format!("{}*", row.node_id),
                    (false, true) => format!("{}L", row.node_id),
                    (false, false) => row.node_id.to_string(),
                };
            let address =
                row.address.map_or("unknown".to_string(), |address| address.addr.to_string());
            let caught_up = match (leading, row.caught_up) {
                (false, _) => "-",
                (true, true) => "yes",
                (true, false) => "no",
            };
            let progress = row.peer.filter(|_| leading);
            let match_index = progress.map_or("-".to_string(), |peer| peer.match_index.to_string());
            let last_contact = row
                .peer
                .and_then(|peer| peer.last_contact)
                .map_or("-".to_string(), |contact| format!("{:.1} s", contact.as_secs_f64()));
            writeln!(
                f,
                "{node:<6} {:<8} {address:<24} {caught_up:<10} {match_index:>10} {last_contact:>13}",
                row.role.to_string()
            )?;
        }
        if members.unlisted > 0 {
            writeln!(f, "{} more members not listed", members.unlisted)?;
        }
        writeln!(f, "* this node, L leader")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use clap::Parser;
    use flux::spine::SpineProducers;
    use silver_common::{Keypair, MembershipError};

    use super::*;
    use crate::args::Args;

    fn parse(args: &[&str]) -> ClusterCommand {
        let args = Args::try_parse_from([&["silver"], args].concat()).unwrap();
        args.command.expect("a cluster command")
    }

    #[test]
    fn subcommands_parse_into_admin_commands() {
        let replace = MembershipOperation::Replace { old: 3, new: 4 };
        let cases = [
            (&["replace", "3", "4"][..], ClusterAdminCommand::Change(replace)),
            (&["transfer-leader", "2"], ClusterAdminCommand::TransferLeader { node_id: 2 }),
            (&["members"], ClusterAdminCommand::Members),
        ];
        for (args, expected) in cases {
            assert_eq!(parse(args).admin_command(), Ok(expected));
        }
        assert!(Args::try_parse_from(["silver", "promote"]).is_err());
    }

    #[test]
    fn member_without_quic_address_is_not_added() {
        let enr = Enr::empty(Keypair::from_secret(&[1; 32]).unwrap().secret_key()).unwrap();
        assert!(ClusterCommand::Add { node_id: 4, enr }.admin_command().is_err());
    }

    #[test]
    fn missing_node_is_reported_without_creating_its_queues() {
        let base = tempfile::tempdir().unwrap();
        assert!(ClusterAdminClient::attach(base.path()).is_err());
        assert!(!shmem_dir_queues_with_base(base.path(), APP_NAME).exists());
    }

    /// Answers each request the way the Control tile does, from another
    /// spine handle on the same directory.
    #[derive(Default)]
    struct NodeTile {
        answered: usize,
    }

    impl Tile<SilverSpine> for NodeTile {
        fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
            adapter.consume(|request: ClusterAdminRequest, producers| {
                let error = MembershipError::NotLeader { leader_id: Some(2), leader_addr: None };
                let result = ClusterAdminResult::Refused(error);
                producers.produce(ClusterAdminResponse { request_id: request.request_id, result });
                self.answered += 1;
            });
        }
    }

    #[test]
    fn request_is_answered_through_the_spine() {
        let base = tempfile::tempdir().unwrap();
        let node_dir = base.path().to_path_buf();
        let (ready, attached) = mpsc::channel();
        let node = thread::spawn(move || {
            let mut tile = NodeTile::default();
            let mut spine = SilverSpine::new_with_base_dir(&node_dir, None);
            let mut adapter = SpineAdapter::connect_tile(&tile, &mut spine);
            adapter.subscribe_broadcast::<ClusterAdminRequest>();
            ready.send(()).unwrap();
            let deadline = Instant::now() + RESPONSE_TIMEOUT;
            while tile.answered == 0 && Instant::now() < deadline {
                tile.loop_body(&mut adapter);
                thread::sleep(POLL_INTERVAL);
            }
        });
        attached.recv().unwrap();

        let mut client = ClusterAdminClient::attach(base.path()).unwrap();
        let request = ClusterAdminRequest { request_id: 9, command: ClusterAdminCommand::Members };
        let result = client.request(request).unwrap();
        node.join().unwrap();
        assert!(matches!(
            result,
            ClusterAdminResult::Refused(MembershipError::NotLeader { leader_id: Some(2), .. })
        ));
    }
}
