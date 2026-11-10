# AI security history sizing

The AI history is additional to the vault, audit, outcome ledger and backups.
It retains at most `security_history.capacity` live records, with a separate
rolling limit per actor and a configured TTL. Capacity must reserve the per-actor
limit for every configured agent that can invoke an inspected route.

The store rejects plaintext records over 16,384 bytes and encrypted records over
32,768 bytes. Multiplying capacity by 32,768 gives a conservative ciphertext
payload allowance: 312.5 MiB at the default 10,000 records, or 3,125 MiB at
100,000 records. These are payload bounds, not filesystem quotas or measured
database sizes. Include SQLite pages, indexes, journals, free space for writes
and copies retained by backup. Expiration and ring replacement delete records;
they do not promise to shrink the database file.

Each read/write verifies the bounded stored history. Its work grows with the
number of retained records. The existing non-AI capacity and endurance results
do not establish throughput for AI-enabled routes, a full history, many actors
or an external model. Provider latency, history occupancy and actor count need
separate measurement for the intended deployment.

Required history read/write failures deny the protected action before business
dispatch. Monitor disk headroom and storage errors and size the filesystem
before enabling the engine. No history retention service, automatic disk quota
or multi-host history coordination is provided by this store.
