# Assumeutxo Design

For notes on the usage of Assumeutxo, please refer to [the usage doc](/doc/assumeutxo.md).

## General background

- [assumeutxo proposal](https://github.com/jamesob/assumeutxo-docs/tree/2019-04-proposal/proposal)
- [Github issue](https://github.com/bitcoin/bitcoin/issues/15605)
- [draft PR](https://github.com/bitcoin/bitcoin/pull/15606)

## Design notes

- The concept of UTXO snapshots is treated as an implementation detail that lives
  behind the ChainstateManager interface. The external presentation of the changes
  required to facilitate the use of UTXO snapshots is the understanding that there are
  now certain regions of the chain that can be temporarily assumed to be valid.
  In certain cases, e.g. wallet rescanning, this is very similar to dealing with
  a pruned chain.

  Logic outside ChainstateManager should try not to know about snapshots, instead
  preferring to work in terms of more general states like assumed-valid. It asks
  `AssumedValidBase()` whether the chainstate is based on a snapshot that is not
  validated yet, `GetHistoricalBlockRange()` which blocks before it still have to
  be downloaded, and `ValidatedTip()` up to which block the chain was connected
  starting from the genesis block.

- There is only one `Chainstate`. Loading a snapshot replaces its UTXO set. The
  previous UTXO set is kept in a separate coins database, the historical coins,
  and `ChainstateManager::AdvanceHistoricalChain()` connects the blocks leading up
  to the snapshot base to it, one at a time and in order. There is no chain
  selection involved since the blocks are the ancestors of the snapshot base. No
  validation interface notifications are sent for them except `BlockChecked`.

- `node::HistoricalReplayVerifier` advances the historical coins on its own thread
  (`b-histverify`). Once they reach the snapshot base, it calls
  `ChainstateManager::ValidateSnapshot()`, which hashes them without holding
  `cs_main`.

## Phases

### "Normal" operation via initial block download

`m_from_snapshot_blockhash` of the chainstate is `std::nullopt` and there are no
historical coins. This is the "traditional" mode of operation for bitcoind.

| directory | contents |
| ---------- | ----------- |
| `chainstate` | UTXO set of the chainstate |

### User loads a UTXO snapshot via `loadtxoutset` RPC

`ActivateSnapshot()` loads the snapshot into a separate coins database in
`chainstate_snapshot` (see `PopulateAndValidateSnapshot()`). The chainstate keeps
using its own coins database in the meantime.

Once the snapshot is loaded and its hash matches the compiled value in
`CMainParams::m_assumeutxo_data`, the base blockhash is written to
`chainstate_snapshot/unvalidated_base_blockhash` and the coins databases are
swapped while holding `cs_main`. `chainstate` is renamed to `chainstate_verify`
and `chainstate_snapshot` to `chainstate`. Then the tip of the chainstate jumps to
the snapshot base. The ancestors of the snapshot base get `BLOCK_OPT_WITNESS`, so
that `NeedsRedownload()` doesn't ask for `-reindex` on startup, and the snapshot
base gets the `m_chain_tx_count` from the chainparams.

| directory | contents |
| ---------- | ----------- |
| `chainstate` | UTXO set of the chainstate, based on the snapshot, and `unvalidated_base_blockhash` |
| `chainstate_verify` | historical coins, which were the UTXO set of the chainstate before |

`unvalidated_base_blockhash` marks the chainstate as based on a snapshot that is
not validated yet. On startup, `LoadAssumeutxoState()` reads it, and the
historical coins are loaded from `chainstate_verify`. If the node shuts down while
the snapshot is loaded, `LoadAssumeutxoState()` removes `chainstate_snapshot` on the
next startup. If it shuts down during the swap, it completes the swap.

### Snapshot chainstate syncs to the tip

The chainstate syncs to the network tip from the snapshot base and gets most of the
cache while it is in initial block download (see `MaybeRebalanceCaches()`). Blocks
before the snapshot base are downloaded as well and connected to the historical
coins as they arrive. If the historical coins follow a branch that does not lead to
the snapshot base, for example because the node synced a stale branch before loading
the snapshot, blocks are disconnected from them until they are back on the path to
the snapshot base. If that fails, the replay starts over from the genesis block.

Once the chainstate leaves initial block download, most of the cache goes to the
historical coins.

A prune lock named `assumeutxo` keeps the blocks from the historical coins tip, as
written to disk, to the snapshot base from being pruned. The chainstate can prune
the blocks before and after them. Blocks after the snapshot base are stored in
separate block files (`BlockfileType::ASSUMED`), because they are downloaded at the
same time as the blocks before it and pruning works on whole files.

Indexes only index blocks up to `ValidatedTip()`, so they wait for the historical
coins while those are behind, and they only consider themselves synced once the
snapshot is validated. `loadtxoutset` restarts them because the chainstate tip jumps.

### Historical coins reach the snapshot base

`ValidateSnapshot()` hashes the historical coins and compares the hash to
`CMainParams::m_assumeutxo_data`.

If it matches, the chainstate is marked `VALIDATED`, `unvalidated_base_blockhash` is
removed and `chainstate_verify` is deleted. All of the cache goes to the chainstate,
and `NODE_NETWORK` is signaled again by nodes that don't prune. A restart is not
necessary. After the next one, the chainstate is indistinguishable from one built by
the traditional IBD process. If the node shuts down before `chainstate_verify` is
deleted, `LoadAssumeutxoState()` deletes it on the next startup.

| directory | contents |
| ---------- | ----------- |
| `chainstate` | UTXO set of the chainstate |

If it doesn't match, which should not happen in practice, the chainstate is marked
`INVALID`, `chainstate_verify` is renamed to `chainstate_fallback` and the node shuts
down with a fatal error. On the next startup, `chainstate` is renamed to
`chainstate_snapshot_INVALID` for diagnosis and `chainstate_fallback` to
`chainstate`. The node then continues to sync from the snapshot base without using
the snapshot.

### Datadirs of older versions

Older versions validated the snapshot with a second chainstate. While validating,
`chainstate` contained the chainstate that was syncing from the genesis block, and
`chainstate_snapshot` contained the snapshot chainstate and its base blockhash in
`base_blockhash`. On startup, `LoadAssumeutxoState()` converts this layout like an
interrupted swap.

Once older versions validated the snapshot, they renamed `chainstate_snapshot` to
`chainstate` on the next startup and left `base_blockhash` in it, which is ignored.

Older versions treat a chainstate that is still based on a snapshot as fully
validated, so downgrading is not supported until the snapshot is validated.

## Invariants

- The snapshot base is in `setBlockIndexCandidates` even if it doesn't have
  `BLOCK_VALID_TRANSACTIONS`, because its block may not be downloaded yet.
- Until all blocks before it are downloaded, the snapshot base is the only block
  whose ancestors have not all been downloaded that has an `m_chain_tx_count`
  (see `CheckBlockIndex()`).
- The historical coins are only accessed while holding `cs_main`, except while
  `ValidateSnapshot()` hashes them, during which they are not resized, written or
  deleted.
