# **Engineering Notebook**

## Project: Chat App (Replication Re-Implementation)  
**Contributors:** Miles Pines and William Zhang  

---

### **Entry 11: March 25, 2025 — Persistent, Fault-Tolerant Replication & Dynamic Server Addition**

**Assignment Overview**  
For this assignment, we took our earlier chat application design and made the back end both persistent and 2-fault tolerant. Specifically, we needed to:

- **Persist messages and account data** so we can stop and restart the service without losing information.  
- **Replicate the back end across multiple processes/machines** (no shared persistent store) to tolerate up to two crash/fail-stop failures.  
- **(Extra Credit)** Dynamically add a new server into the replica set.

---

### Design & Implementation Decisions

1. **Persistent Storage with SQLite**  
   - We replaced our in-memory data structures with a persistent SQLite database.  
   - The schema includes:
     - **accounts** (username, salt, hashed_password)
     - **messages** (ID, sender, recipient, text, delivered flag)
     - **metadata** (tracks the highest message ID via `max_message_id`)
   - This ensures all data remains on disk if the server restarts.

2. **Fault-Tolerant Replication**  
   - **Replication Without Shared Storage**  
     - Each replica keeps its own SQLite database.  
     - All write operations (creating accounts, sending messages, etc.) get forwarded to other replicas so that no single store becomes a bottleneck or point of failure.
   - **State Transfer & Metadata**  
     - A special ReplicationService handles state transfer.  
     - New servers request a snapshot (accounts, messages, and the current `max_message_id`) from a live server, then load it into their local DB.  
     - This allows the new server to continue numbering messages correctly.
   - **2-Fault Tolerance**  
     - With three replicas, the system can keep running even if two fail.  
     - The replication protocol ensures data stays consistent among all active replicas.

3. **Dynamic Server Addition (Extra Credit)**  
   - We built our ReplicationService to allow servers to join on the fly.  
   - A joining server calls `TransferState` to get the latest data, then is added to the replica list.  
   - We tested this by starting multiple servers on different ports and verifying the new server picked up the correct `max_message_id`.

---

### Fault Tolerance, Load-Balancing, and Failover

- **2-Fault Tolerance**  
  With three replicas in our system, we ensure that the service remains operational even if up to two nodes fail. Every write operation is replicated across all servers so that if one or two replicas become unresponsive, the remaining server(s) still hold all critical data. This redundancy minimizes the risk of data loss and service interruption.

- **Failure Handling & Recovery**  
  Our replication protocol actively propagates operations to all replica addresses. When a server fails or a network glitch occurs, errors are logged, and the system continues to process operations on the remaining healthy nodes. Furthermore, if a failed replica is restarted or a new replica is added, it uses the `TransferState` RPC to synchronize its state with the latest snapshot, ensuring a seamless recovery without downtime.

- **Dynamic Load-Balancing and Failover**  
  On the client side, a simple round-robin strategy is implemented in the `retry_rpc` function. This mechanism rotates through the available replicas and automatically skips servers marked as temporarily offline. By dynamically switching to responsive servers, the client maintains consistent performance and balances the load across all replicas.

- **Monitoring and Heartbeats**  
  A continuous heartbeat mechanism is employed to monitor server availability. Each client sends periodic heartbeats to the server, and if a heartbeat is missed, the corresponding server is temporarily marked as unavailable. This real-time monitoring enables rapid detection of failures, allowing the client to re-route requests to operational replicas promptly.

- **Graceful Degradation**  
  In scenarios where multiple failures occur, our design ensures graceful degradation. The service continues to function using the available replicas while persisting data locally via SQLite. Once connectivity or additional replicas are restored, the system synchronizes the state, maintaining overall consistency and data integrity.

---

### Observations & Outcomes

- **Persistence Achieved**  
  - SQLite storage keeps accounts and messages even after a server restart.  
  - `max_message_id` in the metadata table ensures new messages don’t conflict with existing ones.

- **Fault Tolerance**  
  - By running three separate processes (or machines) with their own databases, we can lose two servers and still not lose data.  
  - State transfer worked smoothly, and new dynamic servers got the full data snapshot.

- **Dynamic Addition**  
  - Our extra credit feature was successful. New servers can be spun up, receive a snapshot, and begin serving immediately.  
  - This makes scaling simpler, since new replicas can join without shutting anything down.

- **Testing**  
  - Our tests covered persistence, message ID tracking, and the new dynamic join process. Everything performed as expected.

---

### Public Access with ngrok

During testing on different machines, we discovered we needed a public address for connecting to different machines on different networks. We used [ngrok](https://ngrok.com/) to forward port `50051`, which gave us a URL like `0.tcp.ngrok.io:12345`.  
- We had to **run ngrok first** so that we could have a public address to feed as command line arguments while starting the server and client.
- We also learned to **omit the `tcp://` prefix** in the gRPC client—otherwise, DNS resolution fails because the domain name gets interpreted as `tcp://0.tcp.ngrok.io`, which doesn’t exist.

---

### Conclusion

We successfully re-implemented our chat application’s back end to be persistent and 2-fault tolerant. Each replica has its own SQLite store, and operations are replicated so that no single node or storage becomes a point of failure. The ability to dynamically add new replicas was demonstrated and worked smoothly. This sets us up for more advanced improvements like incremental state transfer and secure (TLS) communication in the future.

---

### Next Steps

- **Stress & Partition Testing**: Try artificially cutting off network connections or overloading a server to see how the system behaves.  
- **Incremental State Transfer**: Instead of transferring the entire snapshot every time a new server joins, transfer only what changed since the last snapshot.  
- **TLS Support**: Secure the gRPC channels between clients and servers.