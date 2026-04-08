// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title NullifierSet
/// @notice Append-only set of nullifiers (uint256) used to prevent double-spends.
/// @dev    Framework primitive shipped by janus-evm. Applications hold a
///         `Set` storage struct and call `markUsed(n)` after a successful
///         proof verification, then `isUsed(n)` to check existence.
///
///         The set is intentionally minimal. Applications layer their own
///         semantics on top — Janus does not know whether a "nullifier" is a
///         shielded note nullifier, a bridge burn id, or anything else.
library NullifierSet {
    /// In-storage nullifier set state.
    struct Set {
        mapping(uint256 => bool) used;
        uint256 cardinality;
    }

    /// @notice Returns true iff `nullifier` has been previously marked.
    function isUsed(Set storage set, uint256 nullifier) internal view returns (bool) {
        return set.used[nullifier];
    }

    /// @notice Mark `nullifier` as used. Reverts if it was already used.
    /// @dev Use this in the success path of a proof-verifying instruction
    ///      so the same proof cannot be replayed.
    function markUsed(Set storage set, uint256 nullifier) internal {
        require(!set.used[nullifier], "NullifierSet: already used");
        set.used[nullifier] = true;
        unchecked {
            set.cardinality += 1;
        }
    }

    /// @notice Number of nullifiers currently in the set.
    function size(Set storage set) internal view returns (uint256) {
        return set.cardinality;
    }
}
