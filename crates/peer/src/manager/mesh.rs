//! Per-topic mesh membership, split by fork domain across a transition.
//!
//! At steady state a topic has one mesh (`Single`). Around a fork the
//! same `GossipTopic` briefly carries two meshes (`Multi`) — the old and
//! new digests — with independent membership, before collapsing back to
//! `Single` once the old domain drains. Scoring and backoff stay keyed by
//! the semantic `GossipTopic`; only membership and forward routing are
//! per-digest.

/// One digest's mesh: the connections we have grafted for `(topic, digest)`.
#[derive(Debug)]
pub(super) struct Mesh {
    pub(super) digest: [u8; 4],
    pub(super) peers: Vec<usize>,
}

impl Mesh {
    fn new(digest: [u8; 4], capacity: usize) -> Self {
        Self { digest, peers: Vec::with_capacity(capacity) }
    }
}

/// The meshes for one topic: one digest normally, two during an overlap.
#[derive(Debug)]
pub(super) enum TopicMeshes {
    Single(Mesh),
    Multi([Mesh; 2]),
}

impl TopicMeshes {
    pub(super) fn single(digest: [u8; 4], capacity: usize) -> Self {
        Self::Single(Mesh::new(digest, capacity))
    }

    pub(super) fn get(&self, digest: [u8; 4]) -> Option<&Mesh> {
        self.iter().find(|m| m.digest == digest)
    }

    pub(super) fn get_mut(&mut self, digest: [u8; 4]) -> Option<&mut Mesh> {
        self.iter_mut().find(|m| m.digest == digest)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &Mesh> {
        let (head, tail): (&Mesh, Option<&Mesh>) = match self {
            Self::Single(m) => (m, None),
            Self::Multi([a, b]) => (a, Some(b)),
        };
        std::iter::once(head).chain(tail)
    }

    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Mesh> {
        let (head, tail): (&mut Mesh, Option<&mut Mesh>) = match self {
            Self::Single(m) => (m, None),
            Self::Multi([a, b]) => (a, Some(b)),
        };
        std::iter::once(head).chain(tail)
    }

    pub(super) fn digests(&self) -> impl Iterator<Item = [u8; 4]> + '_ {
        self.iter().map(|m| m.digest)
    }

    /// Membership is a semantic fact: `true` if `conn` is meshed on any
    /// live digest of this topic.
    pub(super) fn contains(&self, conn: usize) -> bool {
        self.iter().any(|m| m.peers.contains(&conn))
    }

    /// Total meshed connections across all live digests (deduplicated:
    /// counts a peer once even if meshed on both).
    pub(super) fn total(&self) -> usize {
        match self {
            Self::Single(m) => m.peers.len(),
            Self::Multi([a, b]) => {
                a.peers.len() + b.peers.iter().filter(|c| !a.peers.contains(c)).count()
            }
        }
    }

    /// Remove `conn` from every sub-mesh; returns whether it was present.
    pub(super) fn remove(&mut self, conn: usize) -> bool {
        let mut removed = false;
        for mesh in self.iter_mut() {
            if let Some(index) = mesh.peers.iter().position(|c| *c == conn) {
                mesh.peers.swap_remove(index);
                removed = true;
            }
        }
        removed
    }

    /// Whether `digest` is one of the live meshes.
    pub(super) fn has_digest(&self, digest: [u8; 4]) -> bool {
        self.iter().any(|m| m.digest == digest)
    }

    /// Add a second, empty mesh for `digest`. No-op if already present or
    /// already `Multi`.
    pub(super) fn add_digest(&mut self, digest: [u8; 4], capacity: usize) {
        if let Self::Single(existing) = self &&
            existing.digest != digest
        {
            let a = std::mem::replace(existing, Mesh::new(digest, 0));
            *self = Self::Multi([a, Mesh::new(digest, capacity)]);
        }
    }

    /// Collapse to just `keep`'s mesh, returning the peers of the dropped
    /// digest so the caller can PRUNE them. No-op if already `Single(keep)`.
    pub(super) fn keep_only(&mut self, keep: [u8; 4]) -> Vec<usize> {
        let Self::Multi([a, b]) = self else {
            return Vec::new();
        };
        let (kept, dropped) = if a.digest == keep {
            (std::mem::replace(a, Mesh::new([0; 4], 0)), std::mem::replace(b, Mesh::new([0; 4], 0)))
        } else {
            (std::mem::replace(b, Mesh::new([0; 4], 0)), std::mem::replace(a, Mesh::new([0; 4], 0)))
        };
        *self = Self::Single(kept);
        dropped.peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 4] = [0xaa; 4];
    const B: [u8; 4] = [0xbb; 4];

    #[test]
    fn single_multi_single_lifecycle() {
        let mut m = TopicMeshes::single(A, 4);
        m.get_mut(A).unwrap().peers.extend([1, 2]);
        assert!(matches!(m, TopicMeshes::Single(_)));
        assert!(m.contains(1) && m.contains(2));
        assert_eq!(m.total(), 2);

        // Enter overlap: second, empty mesh for B.
        m.add_digest(B, 4);
        assert!(matches!(m, TopicMeshes::Multi(_)));
        assert!(m.has_digest(A) && m.has_digest(B));
        assert_eq!(m.get(B).unwrap().peers.len(), 0);
        m.get_mut(B).unwrap().peers.push(3);
        assert_eq!(m.total(), 3);
        assert_eq!(m.digests().collect::<Vec<_>>(), vec![A, B]);

        // Drain: keep only B; A's peers are returned for pruning.
        let dropped = m.keep_only(B);
        assert_eq!(dropped, vec![1, 2]);
        assert!(matches!(m, TopicMeshes::Single(_)));
        assert!(m.has_digest(B) && !m.has_digest(A));
        assert!(m.contains(3));
    }

    #[test]
    fn remove_clears_all_submeshes_and_total_dedupes() {
        let mut m = TopicMeshes::single(A, 4);
        m.get_mut(A).unwrap().peers.push(1);
        m.add_digest(B, 4);
        m.get_mut(B).unwrap().peers.push(1); // same peer meshed on both
        assert_eq!(m.total(), 1, "a peer on both digests counts once");
        assert!(m.remove(1));
        assert_eq!(m.total(), 0);
        assert!(!m.remove(1));
    }

    #[test]
    fn add_digest_is_noop_when_already_present_or_same() {
        let mut m = TopicMeshes::single(A, 4);
        m.add_digest(A, 4); // same digest: stays Single
        assert!(matches!(m, TopicMeshes::Single(_)));
        m.add_digest(B, 4);
        m.add_digest(B, 4); // already Multi: no panic, no third mesh
        assert_eq!(m.digests().count(), 2);
    }
}
