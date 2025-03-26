# **Engineering Notebook**

## Project: Chat App (Replication Re-Implementation)  
**Contributors:** Miles Pines and William Zhang  

---

### **Entry 11: March 25, 2025 — Persistent, Fault-Tolerant Replication & Dynamic Server Addition**

**Assignment Overview**  
For this assignment, we were tasked with taking one of our earlier design exercises for the chat application and re-implementing it so that the back end is both persistent and 2-fault tolerant. In short, our system had to:  
- **Persist messages and account data** so that the service can be stopped and restarted without losing any information.  
- **Replicate its back end across multiple processes/machines** (without a shared persistent store) to tolerate crash/fail-stop failures.  
- **(Extra Credit)** Dynamically add a new server into the set of replicas.  

**Design & Implementation Decisions**  

1. **Persistent Storage with SQLite:**  
   - We replaced our earlier in-memory data structures with a persistent SQLite store.  
   - The database schema now includes three tables:  
     - **accounts:** Stores username, salt, and hashed password.  
     - **messages:** Stores message records with an assigned message ID, sender, recipient, text, and a new flag, **delivered** (to support non-destructive reads).  
     - **metadata:** Maintains key–value pairs, notably the key `max_message_id` that tracks the highest message ID assigned.  
   - This design ensures that even if the server crashes or is restarted, all account and message data remain intact on disk.

2. **Fault-Tolerant Replication:**  
   - **Replication without a Shared Store:**  
     - Each replica maintains its own persistent SQLite database.  
     - The system replicates operations (account creation, message sending, deletion, etc.) among servers so that no single persistent store becomes a single point of failure.  
   - **State Transfer & Metadata Replication:**  
     - A dedicated replication service was implemented to support state transfer.  
     - When a new (dynamic) server joins, it requests a state snapshot from an existing replica. The snapshot includes the full set of accounts, messages (with their delivered status), and the current `max_message_id` from the metadata table.  
     - The dynamic server loads this snapshot and updates its metadata so that new messages continue the numbering sequence seamlessly.
   - **2-Fault Tolerance:**  
     - By replicating across at least three instances, our system can tolerate two simultaneous crash/fail-stop failures.  
     - Our replication protocol ensures that even if two of the three servers crash, the other server holds the complete persistent state.

3. **Dynamic Server Addition (Extra Credit):**  
   - Our replication service was built from scratch to support dynamic addition of new servers.  
   - A new server can join the replica set by contacting an existing server via the `TransferState` RPC. Once the state is transferred and loaded, the new server is added to the list of replicas.  
   - This dynamic addition was demonstrated by running the system on multiple ports and showing that the dynamic server’s new messages receive IDs that continue from the donor’s maximum (ensuring no reset occurs).

**Observations & Outcomes**  
- **Persistence Achieved:**  
  - The persistent SQLite database ensures that all accounts and messages survive server restarts.  
  - The metadata table reliably tracks the maximum message ID so that even after messages are deleted or marked as delivered, new messages are assigned correct sequential IDs.
- **Fault Tolerance:**  
  - Our replication layer, running on separate machines (or processes) without a shared storage backend, provides resilience against up to two simultaneous failures.  
  - State transfer was successfully demonstrated, and new dynamic servers continued the message sequence without conflicts.
- **Dynamic Addition:**  
  - The extra credit feature worked as planned; new replicas could join on the fly, load the current state, and begin handling client requests immediately.
- **Testing:**  
  - Our unit and integration tests now cover persistence, fault tolerance, and dynamic server addition.  

**Conclusion**  
We re-implemented our chat application’s back end to be both persistent and 2-fault tolerant, without relying on a single shared persistent store. Our design uses a persistent SQLite database (with a metadata table for tracking message IDs), a replication service to transfer state among replicas, and support for dynamic server addition. This design meets the assignment requirements and lays a solid foundation for scaling and further security improvements.

**Next Steps**  
- Conduct stress tests and simulate network partitions to further validate fault tolerance.  
- Enhance dynamic state transfer (e.g., incremental updates) to reduce downtime when new replicas join.  
- Explore adding TLS for secure communication between replicas and clients.