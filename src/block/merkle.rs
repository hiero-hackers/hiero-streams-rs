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

// ─── Inclusion witnesses ────────────────────────────────────────────────────
//
// A [`StreamingTreeHasher`] is a Merkle Mountain Range: after `n` leaves
// the stack holds one perfect-subtree root ("peak") per set bit of `n`,
// largest (leftmost) first, and [`StreamingTreeHasher::root`] folds them
// right-to-left so each earlier peak becomes the left child of the
// accumulating root. A witness for one leaf therefore has three parts:
// its path inside its own peak, the peaks to the left of that peak, and
// the peaks to the right pre-folded into a single hash.

/// Which side of a pairing a witness sibling sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Sibling is the left child; the running hash is the right child.
    Left,
    /// Sibling is the right child; the running hash is the left child.
    Right,
}

/// A Merkle inclusion witness for one leaf of a `StreamingTreeHasher`
/// tree: enough to recompute the root from the leaf alone, in `log₂(n)`
/// hashes plus a handful of peak hashes, without shipping the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MerkleWitness {
    /// Path within the perfect subtree ("peak") containing the leaf,
    /// leaf-to-root order.
    pub siblings: Vec<(Side, [u8; 48])>,
    /// Roots of the peaks to the left of ours, in left-to-right order;
    /// each wraps the accumulator as a left child during the fold.
    pub left_peaks: Vec<[u8; 48]>,
    /// The peaks to the right of ours, pre-folded into a single hash
    /// (`None` when our peak is the rightmost).
    pub right_root: Option<[u8; 48]>,
}

/// Peak boundaries `(start, size)` of an `n`-leaf mountain range, largest
/// (leftmost) peak first — one entry per set bit of `n`.
fn peak_bounds(n: usize) -> Vec<(usize, usize)> {
    let mut peaks = Vec::new();
    let mut start = 0;
    for bit in (0..usize::BITS).rev() {
        let size = 1usize << bit;
        if n & size != 0 {
            peaks.push((start, size));
            start += size;
        }
    }
    peaks
}

/// Root of a perfect subtree over `leaves` (a power-of-two count),
/// pairing adjacent nodes level by level. A single leaf is its own root.
fn perfect_root(leaves: &[[u8; 48]]) -> [u8; 48] {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        let mut i = 0;
        while i < level.len() {
            next.push(hash_internal(&level[i], &level[i + 1]));
            i += 2;
        }
        level = next;
    }
    level[0]
}

/// Fold a run of peak roots the way [`StreamingTreeHasher::root`] does —
/// rightmost as the seed, each earlier peak wrapped as a left child.
fn fold_peaks(roots: &[[u8; 48]]) -> Option<[u8; 48]> {
    let (last, rest) = roots.split_last()?;
    let mut acc = *last;
    for r in rest.iter().rev() {
        acc = hash_internal(r, &acc);
    }
    Some(acc)
}

/// The merkle root over `leaves`, identical to what a
/// `StreamingTreeHasher` fed the same leaves produces.
pub fn merkle_root(leaves: &[[u8; 48]]) -> [u8; 48] {
    let peaks = peak_bounds(leaves.len());
    let roots: Vec<[u8; 48]> = peaks
        .iter()
        .map(|&(start, size)| perfect_root(&leaves[start..start + size]))
        .collect();
    fold_peaks(&roots).unwrap_or_else(|| hash_leaf(&[]))
}

/// Build the inclusion witness for the leaf at `index` in an `n`-leaf
/// `StreamingTreeHasher` tree, or `None` if `index` is out of range for
/// `leaves`. Naive by design: it rebuilds the containing peak's path and
/// the neighbouring peak roots offline from the leaf hashes, which is
/// cheap (48 bytes × leaves).
pub fn witness_for(leaves: &[[u8; 48]], index: usize) -> Option<MerkleWitness> {
    if index >= leaves.len() {
        return None;
    }
    let peaks = peak_bounds(leaves.len());

    // Peak containing the leaf: the last one whose range starts at or
    // before `index`.
    let p = peaks
        .iter()
        .rposition(|&(start, _)| start <= index)
        .expect("every index lies in some peak");
    let (start, size) = peaks[p];

    let peak_leaves = &leaves[start..start + size];
    let siblings = peak_path(peak_leaves, index - start);

    let left_peaks = peaks[..p]
        .iter()
        .map(|&(s, sz)| perfect_root(&leaves[s..s + sz]))
        .collect();
    let right_roots: Vec<[u8; 48]> = peaks[p + 1..]
        .iter()
        .map(|&(s, sz)| perfect_root(&leaves[s..s + sz]))
        .collect();

    Some(MerkleWitness {
        siblings,
        left_peaks,
        right_root: fold_peaks(&right_roots),
    })
}

/// The leaf-to-root sibling path within a single perfect peak.
fn peak_path(peak_leaves: &[[u8; 48]], mut pos: usize) -> Vec<(Side, [u8; 48])> {
    let mut siblings = Vec::new();
    let mut level = peak_leaves.to_vec();
    while level.len() > 1 {
        let (side, sibling) = if pos % 2 == 0 {
            (Side::Right, level[pos + 1])
        } else {
            (Side::Left, level[pos - 1])
        };
        siblings.push((side, sibling));

        let mut next = Vec::with_capacity(level.len() / 2);
        let mut i = 0;
        while i < level.len() {
            next.push(hash_internal(&level[i], &level[i + 1]));
            i += 2;
        }
        level = next;
        pos /= 2;
    }
    siblings
}

/// Recompute the tree root from a leaf and its witness. The fold mirrors
/// `StreamingTreeHasher::root`: climb the peak's path, absorb the
/// pre-folded right peaks as a right child, then wrap the left peaks as
/// left children outermost-last.
pub fn fold_witness(leaf: [u8; 48], w: &MerkleWitness) -> [u8; 48] {
    let mut acc = leaf;
    for (side, sibling) in &w.siblings {
        acc = match side {
            Side::Left => hash_internal(sibling, &acc),
            Side::Right => hash_internal(&acc, sibling),
        };
    }
    if let Some(right) = &w.right_root {
        acc = hash_internal(&acc, right);
    }
    for left in w.left_peaks.iter().rev() {
        acc = hash_internal(left, &acc);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic distinct leaf hashes, so a run reproduces exactly.
    fn leaf(i: usize) -> [u8; 48] {
        hash_leaf(&(i as u64).to_be_bytes())
    }

    fn leaves(n: usize) -> Vec<[u8; 48]> {
        (0..n).map(leaf).collect()
    }

    /// The root a network-validated [`StreamingTreeHasher`] produces.
    fn streaming_root(leaves: &[[u8; 48]]) -> [u8; 48] {
        let mut hasher = StreamingTreeHasher::default();
        for l in leaves {
            hasher.add_leaf(*l);
        }
        hasher.root()
    }

    /// `merkle_root` must equal the streaming hasher over every leaf
    /// count, including powers of two and their neighbours where the
    /// peak structure changes shape.
    #[test]
    fn merkle_root_matches_streaming_hasher() {
        for n in 1..=260usize {
            let ls = leaves(n);
            assert_eq!(merkle_root(&ls), streaming_root(&ls), "count {n}");
        }
    }

    /// Exhaustive fold: for every leaf count and every index, folding the
    /// witness reproduces the streaming-hasher root.
    #[test]
    fn fold_reproduces_root_for_every_leaf() {
        let counts = (1..=130usize).chain([255, 256, 257, 511, 512, 513, 1000, 1023, 1024, 1025]);
        for n in counts {
            let ls = leaves(n);
            let expected = streaming_root(&ls);
            for i in 0..n {
                let w = witness_for(&ls, i).unwrap();
                assert_eq!(fold_witness(ls[i], &w), expected, "count {n}, index {i}");
            }
        }
    }

    #[test]
    fn single_leaf_witness_is_the_leaf() {
        let ls = leaves(1);
        let w = witness_for(&ls, 0).unwrap();
        assert!(w.siblings.is_empty());
        assert!(w.left_peaks.is_empty());
        assert!(w.right_root.is_none());
        assert_eq!(fold_witness(ls[0], &w), streaming_root(&ls));
    }

    #[test]
    fn tampered_leaf_fails() {
        let ls = leaves(37);
        let expected = streaming_root(&ls);
        let w = witness_for(&ls, 11).unwrap();
        let mut bad = ls[11];
        bad[0] ^= 0x01;
        assert_ne!(fold_witness(bad, &w), expected);
    }

    #[test]
    fn reordered_sibling_path_fails() {
        let ls = leaves(50);
        let expected = streaming_root(&ls);
        let w = witness_for(&ls, 9).unwrap();
        assert!(w.siblings.len() >= 2, "need a path to reorder");
        let mut reordered = w.clone();
        reordered.siblings.swap(0, 1);
        assert_ne!(fold_witness(ls[9], &reordered), expected);
    }

    #[test]
    fn wrong_orientation_side_fails() {
        // Pick an index whose first sibling changes the hash when the
        // orientation flips (a left/right swap only matters when the
        // sibling differs from the running hash, which distinct leaves
        // guarantee).
        let ls = leaves(64);
        let expected = streaming_root(&ls);
        let mut w = witness_for(&ls, 5).unwrap();
        w.siblings[0].0 = match w.siblings[0].0 {
            Side::Left => Side::Right,
            Side::Right => Side::Left,
        };
        assert_ne!(fold_witness(ls[5], &w), expected);
    }

    #[test]
    fn out_of_range_index_returns_none() {
        let ls = leaves(5);
        assert!(witness_for(&ls, 5).is_none());
        assert!(witness_for(&ls, 99).is_none());
        assert!(witness_for(&[], 0).is_none());
    }
}
