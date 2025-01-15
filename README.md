# NV-Dedup atop PM Code Base

This repository contains the code base for NV-Dedup (atop PM). The artifact evaluation steps can be obtained from [GogetaFS-AE](https://github.com/GogetaFS/GogetaFS-AE). We now introduce the code base and the branches corresponding to the paper.

- [NV-Dedup atop PM Code Base](#nv-dedup-atop-pm-code-base)
  - [Code Organization](#code-organization)
  - [Branches Corresponding to the Paper](#branches-corresponding-to-the-paper)


## Code Organization

The key files are listed below:

- `dedup.c/dedup.h`: the key deduplication logic implementation. `nova_dedup_new_write` is used to deduplicate data block(s).

- `entry.c/entry.h`: allocate/free entries in PM, and provide thread to manipulate the in-PM entries (e.g., calculating and filling non-cryptographic fingerprint) according to NV-Dedup paper.

## Branches Corresponding to the Paper

- *master*: NV-Dedup with the original implementation.

- *non-crypto*: NV-Dedup without using crypto hash.