Assumeutxo
----------

- A snapshot loaded with `loadtxoutset` now replaces the UTXO set of the
  chainstate directly. The previous UTXO set is kept in a separate
  `chainstate_verify` directory, where the blocks leading up to the snapshot are
  validated in the background, instead of in a second chainstate. Once the
  snapshot is validated, `chainstate_verify` is deleted right away instead of on
  the next restart. The UTXO set hash that this validation computes no longer
  blocks the rest of the node while it is calculated.

- Data directories of previous versions in which a snapshot is being validated
  are converted on startup. Downgrading before the snapshot is validated is not
  supported, because previous versions would treat the snapshot as validated.

- Pruning nodes validating a snapshot no longer split the `-prune` target between
  two chainstates, which kept at least 1100 MiB of blocks. The blocks that the
  background validation still needs are not pruned.
