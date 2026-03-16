RPC
---

The `getblockchaininfo` RPC exposes progress for background validation if the `assumeutxo` feature is used. Previously, `verificationprogress` could return 1.0 and `initialblockdownload` false even if the node was still validating blocks in the background. A new object, `backgroundvalidation`, provides details about the snapshot being validated, including snapshot height, number of blocks processed, best block hash, chainwork, median time, and verification progress.
