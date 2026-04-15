// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Poseidon2} from "./Poseidon2.sol";

/// @title MerkleTree
/// @notice 4-ary append-only Merkle tree backed by Poseidon2 over BN254 Fr.
/// @dev    Framework primitive shipped by genshi-evm. Applications hold a
///         `Tree` storage struct and call `insert` on each new leaf; the
///         current root is exposed via `currentRoot`. Tree depth is set
///         once at construction and applies to every leaf in this tree.
///
///         The tree matches the in-circuit Merkle gadget shipped in
///         genshi-core/src/gadgets/merkle.rs — leaves are hashed up four at a
///         time using `Poseidon2.hash4`, with the special index encoding
///         described in the gadget docs. Applications that consume this
///         contract get a Merkle root that is bytewise-identical to the one
///         their circuits are checking.
///
///         **Storage layout:**
///         - `depth` is set once
///         - `nextIndex` tracks how many leaves have been appended
///         - `filledSubtrees` caches the rightmost frontier nodes per level
///         - `zeros` caches the empty-subtree hash per level
library MerkleTree {
    /// Maximum tree depth supported. Depth is in 4-ary levels, so capacity is 4^depth.
    uint256 internal constant MAX_DEPTH = 16; // 4^16 ≈ 4.3B leaves

    /// In-storage state of an append-only 4-ary Poseidon2 Merkle tree.
    struct Tree {
        uint256 depth;
        uint256 nextIndex;
        // For each level [0..depth), the rightmost subtree node currently in flight.
        // We need 3 cached siblings per level because each parent absorbs 4 children.
        mapping(uint256 => uint256[3]) filledSubtrees;
        // For each level [0..=depth), the hash of an all-empty subtree.
        mapping(uint256 => uint256) zeros;
    }

    /// @notice Initialize an empty tree with the given depth.
    /// @dev Idempotent; subsequent calls revert to prevent re-initialization.
    function init(Tree storage tree, uint256 depth) internal {
        require(tree.depth == 0, "MerkleTree: already initialized");
        require(depth > 0 && depth <= MAX_DEPTH, "MerkleTree: depth out of range");
        tree.depth = depth;
        // Build the empty-subtree hashes bottom-up.
        uint256 z = 0;
        for (uint256 i = 0; i < depth; i++) {
            tree.zeros[i] = z;
            z = Poseidon2.hash4(z, z, z, z);
        }
        tree.zeros[depth] = z;
    }

    /// @notice Append a leaf to the tree and return the new root.
    /// @param tree The tree storage struct.
    /// @param leaf The leaf value to append (must already be a field element).
    /// @return root The Merkle root after the insertion.
    function insert(Tree storage tree, uint256 leaf) internal returns (uint256 root) {
        uint256 idx = tree.nextIndex;
        require(idx < (1 << (2 * tree.depth)), "MerkleTree: full");

        uint256 currentHash = leaf;
        uint256 cursor = idx;
        for (uint256 level = 0; level < tree.depth; level++) {
            uint256 slot = cursor & 3; // which of the 4 children we are in this level
            uint256[3] storage sibs = tree.filledSubtrees[level];

            uint256 a;
            uint256 b;
            uint256 c;
            uint256 d;
            if (slot == 0) {
                // First child in this 4-tuple — store ourselves and use empty siblings.
                sibs[0] = currentHash;
                a = currentHash;
                b = tree.zeros[level];
                c = tree.zeros[level];
                d = tree.zeros[level];
            } else if (slot == 1) {
                sibs[1] = currentHash;
                a = sibs[0];
                b = currentHash;
                c = tree.zeros[level];
                d = tree.zeros[level];
            } else if (slot == 2) {
                sibs[2] = currentHash;
                a = sibs[0];
                b = sibs[1];
                c = currentHash;
                d = tree.zeros[level];
            } else {
                a = sibs[0];
                b = sibs[1];
                c = sibs[2];
                d = currentHash;
            }
            currentHash = Poseidon2.hash4(a, b, c, d);
            cursor >>= 2;
        }

        tree.nextIndex = idx + 1;
        return currentHash;
    }

    /// @notice Compute the current root without inserting.
    /// @dev    O(depth) view; safe to call from off-chain or other contracts.
    function currentRoot(Tree storage tree) internal view returns (uint256) {
        if (tree.nextIndex == 0) {
            return tree.zeros[tree.depth];
        }
        // For an append-only tree, the root is fully determined by the
        // frontier siblings. We walk up the same way `insert` does, except we
        // pretend "the next leaf" is the empty-subtree hash so we observe the
        // current state without modifying anything.
        uint256 idx = tree.nextIndex; // index of the next slot
        uint256 currentHash = tree.zeros[0];
        uint256 cursor = idx;
        for (uint256 level = 0; level < tree.depth; level++) {
            uint256 slot = cursor & 3;
            uint256[3] storage sibs = tree.filledSubtrees[level];
            uint256 a;
            uint256 b;
            uint256 c;
            uint256 d;
            if (slot == 0) {
                a = sibs[0];
                b = sibs[1];
                c = sibs[2];
                d = (idx == 0) ? tree.zeros[level] : currentHash;
            } else if (slot == 1) {
                a = sibs[0];
                b = currentHash;
                c = tree.zeros[level];
                d = tree.zeros[level];
            } else if (slot == 2) {
                a = sibs[0];
                b = sibs[1];
                c = currentHash;
                d = tree.zeros[level];
            } else {
                a = sibs[0];
                b = sibs[1];
                c = sibs[2];
                d = currentHash;
            }
            currentHash = Poseidon2.hash4(a, b, c, d);
            cursor >>= 2;
        }
        return currentHash;
    }
}
