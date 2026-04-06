/**
 * Shroud SDK — Thin JS wrapper around the shroud-wasm module.
 *
 * Handles SRS fetching/caching (IndexedDB) and provides async APIs
 * for browser-based proof generation.
 *
 * Usage:
 *   import init, { prove_transfer, prove_withdraw, compute_commitment, derive_nullifier } from './shroud_wasm.js';
 *   const sdk = new ShroudSDK('https://cdn.example.com/srs.bin');
 *   await sdk.init();
 *   const result = await sdk.proveTransfer(witnessJson);
 */

const IDB_NAME = 'shroud-sdk';
const IDB_STORE = 'srs';
const IDB_KEY = 'srs-bytes';

export class ShroudSDK {
  /**
   * @param {string} srsUrl - URL to fetch the SRS binary from.
   * @param {object} wasm - The initialized WASM module exports.
   */
  constructor(srsUrl, wasm) {
    this.srsUrl = srsUrl;
    this.wasm = wasm;
    this.srsBytes = null;
  }

  /**
   * Load the SRS, using IndexedDB cache if available.
   */
  async loadSRS() {
    // Try cache first
    const cached = await this._idbGet(IDB_KEY);
    if (cached) {
      this.srsBytes = new Uint8Array(cached);
      return;
    }

    // Fetch from CDN
    const resp = await fetch(this.srsUrl);
    if (!resp.ok) throw new Error(`Failed to fetch SRS: ${resp.status}`);
    const buf = await resp.arrayBuffer();
    this.srsBytes = new Uint8Array(buf);

    // Cache in IndexedDB
    await this._idbPut(IDB_KEY, buf);
  }

  /**
   * Generate a transfer proof.
   * @param {string} witnessJson - JSON witness string.
   * @returns {{ proof: Uint8Array, publicInputs: Uint8Array }}
   */
  async proveTransfer(witnessJson) {
    if (!this.srsBytes) await this.loadSRS();
    const result = this.wasm.prove_transfer(witnessJson, this.srsBytes);
    return this._decodeResult(result);
  }

  /**
   * Generate a withdraw proof.
   * @param {string} witnessJson - JSON witness string.
   * @returns {{ proof: Uint8Array, publicInputs: Uint8Array }}
   */
  async proveWithdraw(witnessJson) {
    if (!this.srsBytes) await this.loadSRS();
    const result = this.wasm.prove_withdraw(witnessJson, this.srsBytes);
    return this._decodeResult(result);
  }

  /**
   * Compute a note commitment (no SRS needed).
   * @param {string} noteJson - JSON note string.
   * @returns {Uint8Array} 32-byte commitment.
   */
  computeCommitment(noteJson) {
    return this.wasm.compute_commitment(noteJson);
  }

  /**
   * Derive a nullifier (no SRS needed).
   * @param {string} npHex - Nullifier preimage hex.
   * @param {string} secretHex - Secret hex.
   * @param {bigint|number} leafIndex - Leaf index.
   * @returns {Uint8Array} 32-byte nullifier.
   */
  deriveNullifier(npHex, secretHex, leafIndex) {
    return this.wasm.derive_nullifier(npHex, secretHex, BigInt(leafIndex));
  }

  // ================================================================
  // Internal: decode proof result
  // ================================================================

  _decodeResult(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const proofLen = view.getUint32(0, true); // LE
    const proof = bytes.slice(4, 4 + proofLen);
    const publicInputs = bytes.slice(4 + proofLen);
    return { proof, publicInputs };
  }

  // ================================================================
  // Internal: IndexedDB helpers
  // ================================================================

  _openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(IDB_NAME, 1);
      req.onupgradeneeded = () => {
        req.result.createObjectStore(IDB_STORE);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async _idbGet(key) {
    try {
      const db = await this._openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(IDB_STORE, 'readonly');
        const req = tx.objectStore(IDB_STORE).get(key);
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error);
      });
    } catch {
      return null; // IndexedDB not available
    }
  }

  async _idbPut(key, value) {
    try {
      const db = await this._openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(IDB_STORE, 'readwrite');
        const req = tx.objectStore(IDB_STORE).put(value, key);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
      });
    } catch {
      // IndexedDB not available, skip caching
    }
  }
}
