- Fuse file system
- Files are encrypted
- Store files as content addressed 512kb blobs


File metadata
- path
- key
- part one / parts
- creation date?



---

Write a file
- encrypt file
- split in blocks starting from end
- write metadata to first block
- write block hashes in first block
- 

Encryption?
- per block, per file?

Redundancy?
- reed solomon

Read file?

List file?
1. Scan through all blocks and build an in memory representation
2. have an encrypted file allocation table

FAT
- encrypted
- append only
- store first block

Metadata
- creation time


Payment for storage
- pay daily based on content + unique key to prove 
- maybe for for longer duration by sending a encrypted transaction that will only be decryptable by using the content + unique key. The unique key is part of a sequence the private key holder can predict, but only published each day. Failure to publish at any time could cause nodes to choose to delete data. Access to data will probably also not be provided before storage payment
