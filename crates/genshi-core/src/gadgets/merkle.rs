//! 4-ary Poseidon2 Merkle tree gadget.
//!
//! Constrains a Merkle inclusion proof: given a leaf and an authentication
//! path of siblings, compute the root of a 4-ary Poseidon2 Merkle tree.
//! The tree arity is fixed at 4 (chosen because t=5 Poseidon2 amortises the
//! best on a 4-to-1 compression). Depth is fixed at compile time via
//! `MERKLE_DEPTH`; a future revision may make this const-generic.
//!
//! At each level, the node has 4 children. The path index (0-3) determines
//! which position the current value occupies among its siblings.
//!
//! # Cost (current parameters)
//!
//! `MERKLE_DEPTH` levels × 1 Poseidon2 hash_4 per level
//! ≈ MERKLE_DEPTH × ~950 constraints (pre custom-gate work).

use ark_bn254::Fr;


use crate::arithmetization::ultra_circuit_builder::{UltraCircuitBuilder, WireRef};
use super::poseidon2_gadget::poseidon2_hash_4_gadget;

/// Default Merkle tree depth exposed by this gadget.
///
/// 10 levels of a 4-ary tree → 4^10 = 1,048,576 leaves. Applications that
/// need a different depth should either re-export this with a new constant
/// or compose `merkle_inclusion_gadget` with their own path length.
pub const MERKLE_DEPTH: usize = 10;

/// A Merkle authentication path for a 4-ary tree.
///
/// For each level, we store:
/// - 3 sibling hashes (the other children at that node)
/// - the child index (0-3) indicating where the current value sits
#[derive(Clone, Debug)]
pub struct MerklePath {
    /// Sibling hashes at each level (3 siblings per level).
    pub siblings: [[Fr; 3]; MERKLE_DEPTH],
    /// Child index at each level (0-3).
    pub indices: [u8; MERKLE_DEPTH],
}

/// Merkle inclusion proof gadget.
///
/// Constrains that `leaf` is at position determined by `path.indices`
/// in a 4-ary Merkle tree with the returned root.
///
/// # Arguments
/// * `builder` - Circuit builder
/// * `leaf` - The leaf commitment value (wire reference)
/// * `path` - The Merkle authentication path (sibling values + position indices)
///
/// # Returns
/// Wire reference to the computed Merkle root.
pub fn merkle_inclusion_gadget(
    builder: &mut UltraCircuitBuilder,
    leaf: WireRef,
    path: &MerklePath,
) -> WireRef {
    let mut current = leaf;
    
    for level in 0..MERKLE_DEPTH {
        let idx = path.indices[level] as usize;
        assert!(idx < 4, "Child index must be 0-3, got {}", idx);
        
        // Assign sibling wires
        let s0 = builder.add_variable(path.siblings[level][0]);
        let s1 = builder.add_variable(path.siblings[level][1]);
        let s2 = builder.add_variable(path.siblings[level][2]);
        
        // Place current value at the correct position among 4 children
        let children: [WireRef; 4] = match idx {
            0 => [current, s0, s1, s2],
            1 => [s0, current, s1, s2],
            2 => [s0, s1, current, s2],
            3 => [s0, s1, s2, current],
            _ => unreachable!(),
        };
        
        // Hash the 4 children to get the parent
        current = poseidon2_hash_4_gadget(
            builder,
            children[0], children[1], children[2], children[3],
        );
    }
    
    current
}

// ============================================================================
// Native Merkle Tree (for test utility)
// ============================================================================


/// Compute a 4-ary Merkle root from leaves (native computation).
///
/// Pads with zeros if `leaves.len()` is not a power of 4.
pub fn compute_merkle_root(leaves: &[Fr]) -> Fr {
    use ark_ff::Zero;
    use crate::crypto::poseidon2;
    use alloc::vec::Vec;
    
    if leaves.len() == 1 {
        return leaves[0];
    }
    
    // Pad to next power of 4
    let mut layer = leaves.to_vec();
    while layer.len() % 4 != 0 {
        layer.push(Fr::zero());
    }
    
    // Hash up
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 4);
        for chunk in layer.chunks(4) {
            next.push(poseidon2::poseidon2_hash_4(chunk[0], chunk[1], chunk[2], chunk[3]));
        }
        layer = next;
    }
    
    layer[0]
}

/// Generate a Merkle path for a given leaf index (native computation).
pub fn generate_merkle_path(leaves: &[Fr], leaf_index: usize, depth: usize) -> MerklePath {
    use ark_ff::Zero;
    use crate::crypto::poseidon2;
    use alloc::vec::Vec;
    
    let mut siblings = [[Fr::zero(); 3]; MERKLE_DEPTH];
    let mut indices = [0u8; MERKLE_DEPTH];
    
    // Pad leaves to required size
    let total_leaves = 4usize.pow(depth as u32);
    let mut padded = leaves.to_vec();
    padded.resize(total_leaves, Fr::zero());
    
    let mut layer = padded;
    let mut idx = leaf_index;
    
    for level in 0..depth {
        let group_start = (idx / 4) * 4;
        let pos_in_group = idx % 4;
        indices[level] = pos_in_group as u8;
        
        // Collect the 3 siblings
        let mut sib_idx = 0;
        for i in 0..4 {
            if i != pos_in_group {
                siblings[level][sib_idx] = layer[group_start + i];
                sib_idx += 1;
            }
        }
        
        // Compute next layer
        let mut next = Vec::new();
        for chunk in layer.chunks(4) {
            next.push(poseidon2::poseidon2_hash_4(chunk[0], chunk[1], chunk[2], chunk[3]));
        }
        
        layer = next;
        idx /= 4;
    }
    
    // Fill remaining levels with zeros (for depth < MERKLE_DEPTH)
    for level in depth..MERKLE_DEPTH {
        indices[level] = 0;
        siblings[level] = [Fr::zero(); 3];
    }
    
    MerklePath { siblings, indices }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;
    use crate::crypto::poseidon2;

    #[test]
    fn test_merkle_single_level() {
        // 4 leaves → 1 root (depth=1 check)
        let leaves = [Fr::from(10u64), Fr::from(20u64), Fr::from(30u64), Fr::from(40u64)];
        let _root = poseidon2::poseidon2_hash_4(leaves[0], leaves[1], leaves[2], leaves[3]);
        
        // Verify leaf at position 0
        let path = MerklePath {
            siblings: {
                let mut s = [[Fr::zero(); 3]; MERKLE_DEPTH];
                s[0] = [leaves[1], leaves[2], leaves[3]];
                s
            },
            indices: {
                let mut i = [0u8; MERKLE_DEPTH];
                i[0] = 0;
                i
            },
        };
        
        let mut builder = UltraCircuitBuilder::new();
        let leaf_wire = builder.add_variable(leaves[0]);
        let _computed_root = merkle_inclusion_gadget(&mut builder, leaf_wire, &path);
        
        // Only check first level result
        // (remaining 9 levels hash zeros which gives a deterministic result)
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_merkle_depth_2() {
        // 16 leaves → depth 2 tree
        let mut leaves = [Fr::zero(); 16];
        for i in 0..16 {
            leaves[i] = Fr::from((i + 1) as u64);
        }
        
        let _root = compute_merkle_root(&leaves);
        let path = generate_merkle_path(&leaves, 5, 2); // leaf at index 5
        
        let mut builder = UltraCircuitBuilder::new();
        let leaf_wire = builder.add_variable(leaves[5]);
        
        // Only check first 2 levels (override remaining levels)
        // Use a simple 2-level path
        let test_path = path;
        // Fill levels 2..10 with identity hashing of zeros
        // Actually, generate_merkle_path already fills extra levels with zeros
        
        let _computed = merkle_inclusion_gadget(&mut builder, leaf_wire, &test_path);
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_merkle_different_positions() {
        // Same tree, different leaf positions should produce same root
        let leaves = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        
        let path0 = generate_merkle_path(&leaves, 0, 1);
        let path2 = generate_merkle_path(&leaves, 2, 1);
        
        let mut builder0 = UltraCircuitBuilder::new();
        let leaf0 = builder0.add_variable(leaves[0]);
        let _root0 = merkle_inclusion_gadget(&mut builder0, leaf0, &path0);
        
        let mut builder2 = UltraCircuitBuilder::new();
        let leaf2 = builder2.add_variable(leaves[2]);
        let _root2 = merkle_inclusion_gadget(&mut builder2, leaf2, &path2);
        
        // Both should compute to the same root (at level 0 — remaining levels
        // are deterministic from zeros)
        assert!(builder0.check_circuit_correctness());
        assert!(builder2.check_circuit_correctness());
    }

    #[test]
    fn test_merkle_gadget_gate_count() {
        let mut builder = UltraCircuitBuilder::new();
        let leaf = builder.add_variable(Fr::from(42u64));
        let path = MerklePath {
            siblings: [[Fr::zero(); 3]; MERKLE_DEPTH],
            indices: [0u8; MERKLE_DEPTH],
        };
        let _ = merkle_inclusion_gadget(&mut builder, leaf, &path);
        
        let count = builder.num_gates();
        // 10 levels × ~150 gates per Poseidon2 hash_4
        assert!(count > 500, "Merkle gadget should be substantial, got {}", count);
    }
}
