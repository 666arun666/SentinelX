# M2 Persistence Design Note

## Event Identity Design
To satisfy the architecture's requirement for deterministic event identity (idempotency), SentinelX will generate the `event_id` using a cryptographic hash:

`event_id = SHA-256(source_identity + source_timestamp + raw_event_content)`

For example, `source_identity` can refer to `auth.log` or `journalctl`. By combining this with the raw event string and timestamp, we establish a unique identifier resistant to rotation duplications and process restarts. 

## Timestamp Design
The architecture requires clear timestamp normalization:
- `event_time`: The explicit timestamp provided by the source log, converted and normalized to UTC. If a timezone is absent, the system's local timezone assumption is used and mapped to UTC.
- `collected_at`: The physical UTC timestamp when the SentinelX collector processes the event.

## Persistence Strategy
- **At-Least-Once Delivery**: SentinelX is designed with at-least-once ingestion. If the process is killed midway, events may be re-read upon restart.
- **Idempotent Storage**: PostgreSQL will utilize `ON CONFLICT (event_id) DO NOTHING` logic. Combined with our stable event hashes, duplicates re-read after process restarts are safely discarded without application side-effects.
- **Source Cursors**: In M2, file collectors will track the file `inode` and `offset` state. Journal collectors will track cursors. State bounds are utilized to minimize re-reading historical data, but the idempotent DB remains the ultimate guardrail.
- **Log Rotation**: Relying on `inode` tracking allows the collector to detect file rotation. The old inode can be exhausted before opening the newly rotated log file payload, averting data loss.
- **Backpressure & Concurrency**: The persistence layer should handle database connection pools efficiently and implement a bounded queue. A single-instance monitor guard must be instituted to prevent concurrent duplicate collectors from running on the exact same log sources.
