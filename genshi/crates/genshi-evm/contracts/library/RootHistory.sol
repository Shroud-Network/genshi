// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title RootHistory
/// @notice Fixed-capacity circular buffer of recent Merkle roots.
/// @dev    Framework primitive shipped by genshi-evm. Applications use this to
///         accept proofs that reference any root produced in the recent past
///         (typically the last ~100 deposits) so users can sign transactions
///         offline without racing against the on-chain root.
///
///         The buffer never resizes and never reverts on overflow — once it
///         is full, the oldest root is overwritten. Applications can pin the
///         capacity at construction by calling `init`.
library RootHistory {
    /// Default capacity if `init` is called without a value. Tuned for
    /// roughly 30 minutes of history at one deposit per block.
    uint256 internal constant DEFAULT_CAPACITY = 100;

    /// In-storage circular buffer state.
    struct History {
        uint256 capacity;
        uint256 head; // index where the next push will land
        uint256 length; // number of valid roots, capped at `capacity`
        mapping(uint256 => uint256) roots; // index in [0, capacity) -> root
        mapping(uint256 => bool) known; // root -> contained
    }

    /// @notice Initialize the buffer with the given capacity. Must be called once.
    function init(History storage history, uint256 capacity) internal {
        require(history.capacity == 0, "RootHistory: already initialized");
        require(capacity > 0, "RootHistory: capacity must be positive");
        history.capacity = capacity;
    }

    /// @notice Initialize with the default capacity.
    function initDefault(History storage history) internal {
        init(history, DEFAULT_CAPACITY);
    }

    /// @notice Append a root to the buffer. Overwrites the oldest entry once full.
    function push(History storage history, uint256 root) internal {
        require(history.capacity > 0, "RootHistory: not initialized");

        uint256 idx = history.head;
        if (history.length == history.capacity) {
            // Overwriting an old slot — drop it from the `known` map first.
            uint256 stale = history.roots[idx];
            history.known[stale] = false;
        } else {
            unchecked {
                history.length += 1;
            }
        }

        history.roots[idx] = root;
        history.known[root] = true;

        unchecked {
            history.head = (idx + 1) % history.capacity;
        }
    }

    /// @notice Returns true iff `root` is currently in the buffer.
    function contains(History storage history, uint256 root) internal view returns (bool) {
        return history.known[root];
    }

    /// @notice Number of roots currently stored.
    function size(History storage history) internal view returns (uint256) {
        return history.length;
    }
}
