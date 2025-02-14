# **Engineering Notebook**

## Project: Chat App  
**Contributors:** Miles Pines and William Zhang  

---

### **Entry 1: Feb 3, 2025 — Initial Setup**

**Goal / Hypothesis**  
- Create a minimal client-server architecture using Python `socket` and `threading`.  
- Hypothesis: “If I run each client in its own thread on the server side, I can handle multiple connections simultaneously without major blocking issues.”

**How**  
1. Started a `ChatServer` class in `server.py`.  
2. Used `socket.accept()` in a loop, spawning a new thread (`handle_client()`) for each connection.  
3. Created a bare-bones `ChatClient` in `client.py` that connects to the server and sends a test message.

**Observations**  
- With a couple of test clients, the server spawns multiple threads and handles them fine.  
- No major concurrency problems with light usage.

**Data Analysis**  
- Basic concurrency proof-of-concept works; no deadlocks or crashes in a small test.

**Next Steps**  
- Implement actual commands (create account, login, etc.).  
- Decide on the two protocols (custom binary vs. JSON) and see how to integrate them.

---

### **Entry 2: Feb 5, 2025 — Designing Wire Protocols**

**Goal / Hypothesis**  
- Outline a **Custom Binary Protocol** vs. a **JSON Protocol** for sending commands and fields over the network.  
- Hypothesis: “The custom binary protocol will produce smaller messages and be more efficient than JSON.”

**How**  
1. For **Custom Binary**:  
   - Command is 1 byte (integer).  
   - 4-byte payload length.  
   - Payload has multiple fields, each with a 2-byte length followed by UTF-8 bytes.  
2. For **JSON**:  
   - 4-byte length of a JSON string.  
   - The JSON string includes `"command"` (string) and `"fields"` (list of strings).  

**Observations**  
- Encoding/decoding logic is straightforward to implement in Python (using `struct` for binary).  
- More lines of code for custom parsing, but it’s not too complicated.

**Data Analysis**  
- Expect smaller payloads in the custom protocol (fewer braces, no field names in JSON).

**Next Steps**  
- Implement code for both `CustomProtocol` and `JSONProtocol` classes in both `server.py` and `client.py`.  
- Test actual message sizes.

---

### **Entry 3: Feb 6, 2025 — Account Creation & Password Security**

**Goal / Hypothesis**  
- Implement “CREATE_ACCOUNT” in both protocols, ensuring we do **salted + hashed** passwords on the server.  
- Hypothesis: “Storing only the salted hash (PBKDF2-HMAC-SHA256, 400k iterations) is secure enough for this assignment, though we must remember the plaintext password is traveling over the wire in clear text.”

**How**  
1. Added `hash_password` in `server.py` that uses `os.urandom(16)` to create a salt, then PBKDF2 with 400k iterations.  
2. On receiving “CREATE_ACCOUNT” (or `CMD_CREATE_ACCOUNT`), the server checks if the username already exists. If not, store `salt.hex()`, `hashed_password.hex()` in an `Account` object.  
3. The client’s GUI has “Username” and “Password” fields. Clicking **Create Account** sends the plaintext password.  

**Observations**  
- Verified the hashing flow: If I re-run the same password with the same salt, I get the same hash. If salt changes, so does the hash.  
- Danger: We’re not using TLS, so the password is transmitted in plaintext. (Acceptable for demonstration but not recommended in production.)

**Data Analysis**  
- Execution is still quite fast for a handful of test accounts; 400k PBKDF2 rounds is okay for small-scale usage.

**Next Steps**  
- Implement `LOGIN` (or `CMD_LOGIN`), verifying the password by re-computing the hash with the stored salt.

---

### **Entry 4: Feb 7, 2025 — Login & Tracking Online Users**

**Goal**  
- Implement a login flow that sets `account.online = True` when a user logs in.  
- Keep track of the socket (`conn`) and `protocol` in the `Account` object for possible immediate message delivery.

**How**  
1. Added `CMD_LOGIN` or `"LOGIN"` handling:  
   - Server re-hashes the provided password with the stored salt.  
   - If hashes match, set `logged_in_user = username`, `account.online = True`, `account.conn = conn`, etc.  
2. If login fails, send an error via the “RESPONSE” or `CMD_RESPONSE` message.

**Observations**  
- Once a user logs in, they receive a “Login successful” message with the count of unread (actually, total stored) messages.  
- If the same user logs in from another client, the code marks the old session offline. (Currently we do that only if the user actually logs out or the socket closes. That’s good enough for the assignment.)

**Data Analysis**  
- Confirmed that the server sets `online = True` so we can push new messages in real time if the user is connected.

**Next Steps**  
- Implement sending messages (`CMD_SEND_MESSAGE` / `"SEND_MESSAGE"`) and reading them (`CMD_READ_MESSAGES` / `"READ_MESSAGES"`).

---

### **Entry 5: Feb 9, 2025 — Sending & Reading Messages**

**Goal**  
- Finish the core chat functionality: users can send messages to offline or online recipients, and read them.  

**How**  
1. **Sending Messages**  
   - On `SEND_MESSAGE`, the server looks up the recipient `Account` and assigns a unique `msg_id` (taken from `account.next_msg_id`).  
   - Appends a tuple `(msg_id, sender, text)` to `recipient_account.messages`.  
   - If `recipient_account.online`, server tries to push it immediately via `CMD_NEW_MESSAGE` or `"NEW_MESSAGE"`.  
2. **Reading Messages**  
   - On `READ_MESSAGES`, the client can request up to `N` messages.  
   - The server slices `account.messages[:N]`. (Important note: **the server doesn’t remove them** from the list automatically—it just shows the user the first N.)  
   - The user can see them in the chat client text area.

**Observations**  
- Verified that if the recipient is offline, the message just sits in `messages`. When they eventually log in (or request `READ_MESSAGES` if they’re already logged in), they see it.  
- The client’s `“READ MESSAGES”` button calls a simple dialog to pick how many messages to retrieve.  

**Data Analysis**  
- Storing messages in memory is fine for this assignment. No persistence yet.  
- If the user never deletes messages, they will accumulate. (We rely on the `“DELETE_MESSAGES”` command to prune them.)

**Next Steps**  
- Implement `“DELETE_MESSAGES”` to remove specific message IDs.  
- Possibly run concurrency tests to ensure no big issues with the lock.

---

### **Entry 6: Feb 10, 2025 — Deleting Messages & Listing Accounts**

**Goal**  
- Implement `CMD_DELETE_MESSAGES` / `"DELETE_MESSAGES"`.  
- Implement listing accounts (`CMD_LIST_ACCOUNTS` / `"LIST_ACCOUNTS"`) with wildcard patterns.

**How**  
1. **Delete Messages**  
   - The server code expects a list of message IDs as strings.  
   - It filters out any message whose `msg_id` is in that set, effectively removing them.  
2. **List Accounts**  
   - Optionally match a wildcard pattern (like `'*'`) using `fnmatch`.  
   - Return the list of matching usernames as extra fields in a single response.

**Observations**  
- For deletion, the user must pass message IDs. If they type them incorrectly, it won’t match.  
- For listing, we can pass an empty pattern for “all accounts”.

**Data Analysis**  
- The `list_accounts` call just returns many fields in a single response. That seems to work fine in both protocols.

**Next Steps**  
- Add `“DELETE_ACCOUNT”` to remove the entire user account.  

---

### **Entry 7: Feb 11, 2025 — Deleting an Account & Concurrency Checks**

**Goal**  
- `CMD_DELETE_ACCOUNT` / `"DELETE_ACCOUNT"` allows a user to remove their entire account (requires username & password again).  
- Run basic concurrency tests with multiple parallel clients.

**How**  
1. **Delete Account**  
   - On receiving “DELETE_ACCOUNT,” the server re-checks the password. If correct, it calls `del self.accounts[username]`.  
   - Closes the connection.  
2. **Concurrency**  
   - Wrote a small script that spawns 5 clients, each logs in, sends a message, reads messages, then logs out.  
   - Observed CPU usage and any thread collisions.

**Observations**  
- Everything is stable. The single `self.lock` protects the shared dictionary.
- `del self.accounts[username]` removes all messages for that user. They vanish from memory.

**Data Analysis**  
- 2–5 concurrent clients is fine on a typical dev machine. For serious scale, we might consider an async approach, but for the assignment, this is acceptable.

**Next Steps**  
- Final checks: ensure the client’s Tkinter GUI flows match all commands.  
- Prepare for code review.

---

### **Entry 8: Feb 12, 2025 — Protocol Size Test & Final Observations**

**Goal**  
- Compare message sizes for a typical “create account” or “send message” in custom vs. JSON protocol.  
- Summarize project status.

**How**  
1. Created a small script to encode identical data in both protocols.  
2. Measured byte lengths for the `CREATE_ACCOUNT` command with `[username, hashed_pw]`.  
3. Observed overhead reduction in the custom protocol.

**Observations**  
- As expected, JSON is more verbose (`"command":"CREATE_ACCOUNT"`, etc.).  
- For bigger messages or high-frequency usage, the difference could add up.

**Data Analysis**  
- We confirm that the final code reflects these differences. The server and client can be launched with `--protocol custom` or `--protocol json`.

---

### **Entry 9: Feb 14, 2025 — Conclusion, Tests, & Future Ideas**

**Summary of the System**  
1. **Wire Protocols**  
   - **Custom Binary:** More compact, less overhead.  
   - **JSON:** More verbose but easier to debug (just print the JSON string).  
2. **Password Handling**  
   - Plaintext from client, but server does `salt + PBKDF2-HMAC-SHA256 (400k iter)`.  
   - Must rely on TLS in a real scenario—currently, it’s not fully secure in transit.  
3. **Message Handling**  
   - Messages are stored in-memory `(msg_id, sender, text)`.  
   - **READ_MESSAGES** returns the first N from the list but does **not** remove them. The user can call `DELETE_MESSAGES` by ID to remove them.  
   - If recipient is online, the server attempts `CMD_NEW_MESSAGE` / `"NEW_MESSAGE"` push immediately.  
4. **Concurrency**  
   - One thread per client, using a global lock for the account dictionary.  
   - Scales to small concurrency; might be limited for higher loads.  
5. **Deleting Account**  
   - `DELETE_ACCOUNT` requires username & password again. If correct, the server removes that user.

**Tests Implemented**  
- **Unit Tests** (`test_unit.py`):  
  - Tests individual components (e.g., `hash_password` function, `CustomProtocol` and `JSONProtocol` encoding/decoding) with a fake socket to avoid network overhead.  
  - Confirm we get consistent hashes for the same salt, different ones for different salts, etc.

- **Integration Tests** (`test_chat.py`):  
  - Spin up the **actual** server in a background thread.  
  - Tests cover end-to-end scenarios: account creation, login, sending/reading/deleting messages, listing accounts, deleting accounts.  
  - Verified everything works for both protocols (`custom` on one port, `json` on another).

- **Efficiency Tests** (`test_efficiency.py`):  
  - Compare **actual byte sizes** for custom protocol vs. JSON.  
  - Script prints out the size for a `“CREATE_ACCOUNT”` command with given fields.  
  - Confirms an overhead reduction with custom binary.

**Ideas for Future Work**  
- **Persistence**: Store accounts/messages in a database so restarts don’t erase data.  
- **TLS**: Add encryption to secure the plaintext password in transit.  
- **Asynchronous I/O**: Switch from threads to `asyncio` if we want to handle thousands of clients.  
- **Better GUI**: Possibly show a separate chat window per conversation or add message timestamps.