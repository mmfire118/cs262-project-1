# **Engineering Notebook**

## Project: Chat App (gRPC Re-Implementation)  
**Contributors:** Miles Pines and William Zhang  

---

### **Entry 10: Feb 24, 2025 — Transition to gRPC & Evaluation**

**Goal / Hypothesis**  
- **Goal:** Replace the custom binary/JSON protocols with gRPC to improve maintainability, scalability, and overall efficiency.  
- **Hypothesis:** “Switching to gRPC will simplify development by leveraging auto-generated code and provide highly compact binary serialization using Protocol Buffers, all while maintaining (or even reducing) the data payload size compared to our previous approaches. Despite introducing a new abstraction layer, the benefits in code clarity and cross-language support will outweigh the initial integration challenges.”

**How**  
1. **Tool Integration:**  
   - Defined a `chat.proto` file outlining service methods (e.g., `CreateAccount`, `Login`, `SendMessage`, etc.) along with a streaming RPC (`MessageStream`).
   - Generated Python stubs using `grpc_tools.protoc` and integrated them into `grpc_server.py` and `grpc_client.py`.
2. **Client Changes:**  
   - Replaced manual socket communication with gRPC channel creation.
   - Abstracted network calls using the generated `ChatServiceStub`.
   - The existing Tkinter UI remains unchanged; only the underlying communication mechanism was refactored.
3. **Server Changes:**  
   - Implemented service methods directly from the proto definitions.
   - Replaced manual message parsing with automatic Protocol Buffer deserialization.
   - Utilized a thread pool for handling incoming RPC calls and a generator for streaming messages.

**Observations**  
- **Ease of Use:**  
  - **Client:**  
    - gRPC abstracts the networking details, making remote procedure calls as simple as local function calls.
    - The client’s code structure remains largely the same apart from the removal of custom serialization logic.
  - **Server:**  
    - The server code is simplified by using auto-generated classes, significantly reducing boilerplate.
    - There was an initial learning curve and some debugging challenges during configuration, but these were overcome.
- **Data Size:**  
  - Our efficiency tests (see `test_efficiency_grpc.py`) reveal that a sample account creation message serialized with Protocol Buffers is only **18 bytes**, compared to **81 bytes** using our custom binary protocol and **125 bytes** using JSON.  
  - This compact serialization drastically reduces the data payload, which is beneficial for bandwidth and performance.
- **Structural Impact:**  
  - **Client:**  
    - The integration of a gRPC stub replaces our custom wire protocol logic.
    - The overall UI remains unchanged, while the networking layer is now handled by the generated code.
  - **Server:**  
    - The server now implements clearly defined service methods rather than manually handling raw socket data.
    - This change centralizes protocol handling within the auto-generated code, enabling developers to focus solely on business logic.
- **Testing Changes:**  
  - **Unit Testing:**  
    - Unit tests now verify the functionality of utility functions, data models, and the compact serialization of Protocol Buffers (as demonstrated in `test_unit_grpc.py` and `test_efficiency_grpc.py`).
    - The extremely small message sizes are directly measurable, which wasn't possible with our previous custom protocols.
  - **Integration Testing:**  
    - With gRPC, we can directly invoke service methods via stubs, making end-to-end tests more straightforward and reliable.
    - gRPC’s built-in error codes and timeouts simplify the simulation of network conditions and improve test robustness.

**Data Analysis**  
- The adoption of gRPC not only maintains the compact data payload of our custom binary protocol but reduces it further (from 81 bytes or 125 bytes down to 18 bytes for a sample account creation message).  
- This reduction in data size contributes to faster transmissions and lower bandwidth usage, which is particularly advantageous in high-frequency messaging scenarios.
- The refactoring cleanly separates network handling from business logic on the server side, enhancing long-term scalability.

**Conclusion**  
- **Easier or More Difficult?**  
  - While the initial setup and configuration of gRPC was a bit challenging, the overall development process is simplified. Auto-generated stubs eliminate custom serialization code, reducing complexity and potential bugs.
- **Data Size Impact:**  
  - Protocol Buffers provide a remarkably compact binary format. Our tests show a reduction from 81–125 bytes (custom/JSON) to just 18 bytes for similar messages.
- **Structural Changes:**  
  - The **client** now leverages a gRPC stub to handle network operations, leaving the UI intact.
  - The **server** is restructured to implement service methods directly, with all low-level message handling managed by the generated code.
- **Testing Impact:**  
  - Both unit and integration testing have become more streamlined. gRPC’s standardized interfaces and built-in features (error handling, timeouts) reduce the need for extensive custom tests, making our testing more reliable and easier to maintain.

**Next Steps**  
- Finalize integration tests to ensure that all service methods behave as expected under varying network conditions.
- Explore adding TLS to secure communication.
- Consider additional gRPC features (such as deadlines and retries) to further improve robustness.
- Continue benchmarking message sizes and throughput to validate performance improvements.