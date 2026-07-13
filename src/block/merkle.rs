//! The block merkle tree hasher — the consensus node's streaming tree.
//!
//! SHA-384 with a domain prefix byte: `0x00` for leaves, `0x02` for
//! two-child internal nodes, `0x01` for the single-child node at the top
//! of the fixed tree. [`StreamingTreeHasher`] mirrors the consensus
//! node's `NaiveStreamingTreeHasher`; [`super::material`] folds five of
//! these subtree roots into the block root.

use sha2::{Digest, Sha384};

pub(super) const HASH_LENGTH: usize = 48;

pub(super) fn hash_leaf(leaf_bytes: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update([0x00]);
    hasher.update(leaf_bytes);
    hasher.finalize().into()
}

pub(super) fn hash_internal(left: &[u8], right: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update([0x02]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub(super) fn hash_internal_single_child(child: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update([0x01]);
    hasher.update(child);
    hasher.finalize().into()
}

/// Binary-counter merkle fold: after each leaf, pairs collapse while the
/// leaf count's trailing bits are 1, so the stack holds one subtree root
/// per set bit. [`root`](StreamingTreeHasher::root) folds the stack
/// right-to-left, pairing the leftover subtrees exactly as the consensus
/// node's `NaiveStreamingTreeHasher` does.
#[derive(Default)]
pub(super) struct StreamingTreeHasher {
    stack: Vec<[u8; 48]>,
    leaf_count: u64,
}

impl StreamingTreeHasher {
    pub(super) fn add_leaf(&mut self, hash: [u8; 48]) {
        self.stack.push(hash);
        let mut n = self.leaf_count;
        while n & 1 == 1 {
            let right = self.stack.pop().expect("fold-up underflow");
            let left = self.stack.pop().expect("fold-up underflow");
            self.stack.push(hash_internal(&left, &right));
            n >>= 1;
        }
        self.leaf_count += 1;
    }

    pub(super) fn root(self) -> [u8; 48] {
        match self.stack.split_last() {
            None => hash_leaf(&[]),
            Some((last, rest)) => {
                let mut root = *last;
                for hash in rest.iter().rev() {
                    root = hash_internal(hash, &root);
                }
                root
            }
        }
    }
}
