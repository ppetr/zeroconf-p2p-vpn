//! Resolves peer names (the `[peers]` config table keys) to their negotiated VPN addresses over
//! DNS, by implementing `dns_stack::dns::Resolver` over a live name -> addresses map that
//! `session.rs` updates as peers connect and disconnect.

use std::net::IpAddr;

use async_trait::async_trait;
use dashmap::DashMap;
use dns_stack::dns::{matches_suffix, Answer, Query, Reply, Resolver};

/// Live peer-name -> VPN-address mapping, served as DNS answers under `suffix`. Queries outside
/// `suffix` are `Reply::NotMine`, so the host's other configured resolvers still work.
#[derive(Debug)]
pub struct PeerNames {
    suffix: String,
    addresses: DashMap<String, Vec<IpAddr>>,
}

impl PeerNames {
    pub fn new(suffix: String) -> Self {
        Self { suffix, addresses: DashMap::new() }
    }

    /// Records `name`'s currently negotiated addresses, replacing whatever was there before.
    pub fn set(&self, name: &str, addrs: Vec<IpAddr>) {
        self.addresses.insert(name.to_ascii_lowercase(), addrs);
    }

    /// Removes `name` entirely, e.g. once its session ends for good.
    pub fn remove(&self, name: &str) {
        self.addresses.remove(&name.to_ascii_lowercase());
    }
}

#[async_trait]
impl Resolver for PeerNames {
    async fn resolve(&self, query: &Query) -> Reply {
        if !matches_suffix(&query.name, &self.suffix) {
            return Reply::NotMine;
        }
        // `query.name` is already ASCII-lowercased by `dns_stack::dns::handle_packet`, matching
        // the keys `set`/`remove` store.
        let label = query.name[..query.name.len() - self.suffix.len()].trim_end_matches('.');
        if label.is_empty() {
            return Reply::NxDomain;
        }
        match self.addresses.get(label) {
            Some(addrs) => Reply::Answer(Answer::Addrs(addrs.clone())),
            None => Reply::NxDomain,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_stack::dns::RecordKind;

    fn query(name: &str) -> Query {
        Query::new(name, RecordKind::Aaaa)
    }

    fn addr() -> IpAddr {
        "fdbd:a6ce:654d::1".parse().unwrap()
    }

    #[tokio::test]
    async fn refuses_names_outside_the_suffix() {
        let names = PeerNames::new("p2p".to_string());
        assert!(matches!(names.resolve(&query("example.com")).await, Reply::NotMine));
    }

    #[tokio::test]
    async fn answers_a_known_peer_name() {
        let names = PeerNames::new("p2p".to_string());
        names.set("alice", vec![addr()]);

        match names.resolve(&query("alice.p2p")).await {
            Reply::Answer(Answer::Addrs(addrs)) => assert_eq!(addrs, vec![addr()]),
            _ => panic!("expected an answer"),
        }
    }

    #[tokio::test]
    async fn nxdomain_for_unknown_or_removed_peer_names() {
        let names = PeerNames::new("p2p".to_string());
        names.set("alice", vec![addr()]);
        names.remove("alice");

        assert!(matches!(names.resolve(&query("alice.p2p")).await, Reply::NxDomain));
        assert!(matches!(names.resolve(&query("bob.p2p")).await, Reply::NxDomain));
    }

    #[tokio::test]
    async fn nxdomain_for_the_bare_suffix() {
        let names = PeerNames::new("p2p".to_string());
        assert!(matches!(names.resolve(&query("p2p")).await, Reply::NxDomain));
    }

    #[tokio::test]
    async fn peer_names_are_stored_case_insensitively() {
        let names = PeerNames::new("p2p".to_string());
        names.set("Alice", vec![addr()]);

        // `handle_packet` lowercases the query name before `resolve` ever sees it; simulate that
        // here rather than depending on it.
        match names.resolve(&query("alice.p2p")).await {
            Reply::Answer(Answer::Addrs(addrs)) => assert_eq!(addrs, vec![addr()]),
            _ => panic!("expected an answer"),
        }
    }
}
