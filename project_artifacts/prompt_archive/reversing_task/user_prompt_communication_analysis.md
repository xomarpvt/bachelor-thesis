# Task

Your task is to extract, analyze, and document the **Communication Layer** from a malware sample belonging to the {{malware_family}} botnet family.

The objective is to provide a complete, implementation-ready technical specification of the malware's **Session Establishment** and the **Command Processing** loop.

This includes all authentication mechanisms, handshake messages, key exchanges, session identifiers, and protocol interactions involved in establishing a valid C2 session.

For the command processing lifecycle, include how the malware receives, decodes, interprets, validates, and dispatches C2 commands, with all message formats, parsing logic, cryptographic operations, execution flow and response generation.

Focus on these components, explaining every mechanism directly related to them. Do not investigate or document any other functionality unless it is required to explain the authentication process or the main execution loop.

The malware sample is already loaded and open in Ghidra. Perform all reverse engineering and analysis using Ghidra's tools. The sandbox environment is isolated from the malware file, do not attempt to access the malware from there.

{{malware_guide}}

# Required Analysis

**1. Handshake & Authentication**

Document the full session establishment and authentication mechanism:
- **Handshake initiation:** Exact structure, framing, delimiters, and byte sequences sent by the malware to initiate the session
- **Identity verification mechanism:** Technical implementation of how the malware proves identity to the C2 (e.g., hardcoded tokens, dynamic credentials, challenge-response cryptographic handshakes)
- **Credentials:** Explicit handshake password/token values if required
- **Fingerprinting behavior:** If fingerprinting or reconnaissance occurs during handshake, describe the technique and data collected
- **Server response:** Expected initial response from C2, with validation logic, session acceptance criteria and failure handling

**2. Cryptography**

Document all cryptographic and encoding mechanisms used in C2 communication:
- **Algorithms used:** Identify every encryption or encoding routine applied to C2 messages (XOR operations, AES, RC4, Base64, custom algorithms, or combinations) if present
- **Implementation details:** For each algorithm, provide exact implementation details (mode of operation, key length, block size)
- **Cryptographic constants:** Hardcoded keys, initialization vectors (IVs), nonces, salts, or dynamic key derivation routines
- **Handshake vs runtime crypto:** If decryption algorithms differ between handshake and command phases, specify each algorithm and its associated parameters separately

**3. Command Semantics & Attacks Specification**

Document the complete command processing protocol and command execution semantics:
- **Decryption & Decoding Procedures:** Routine required to transition from raw wire bytes to the decoded message   structure
- **Parsing & Message Structure:** Document the message format, framing, field layout, delimiters, length fields, headers, checksums, and serialization format if custom or non-standard
- **Opcode Interpretation & Definitions:** Provide a complete breakdown of the decoded payload structure (e.g., command ID/opcode offsets, parameter lengths, arguments), and define the operational meaning and behavior of every identified opcode
- **Attack Specification:** For every attack-related opcode, document the attack type, required parameters, configurable options, target specification, duration, and any protocol-specific behavior
- **Dynamic Registration:** Check whether the malware supports dynamic registration of commands or attack methods at runtime. If present, document the registration mechanism and dispatch logic

**4. Protocol Feedback Loop**

Document the mechanisms used to maintain the session and report execution status to the C2:
- **Command Responses:** Response messages or acknowledgments (ACKs) sent back to the server upon successful command reception, execution, or failure, including their structure and semantics
- **Heartbeat / Keepalive:** Regular heartbeat or keepalive payload structures, transmission intervals, timeout behavior, and reconnect conditions
- **Status Reporting:** Any periodic or event-driven status updates, execution results, telemetry, error reporting, or victim information transmitted back to the C2
- **Session Lifecycle:** Session maintenance, sequence numbers, message IDs, state transitions, graceful termination, and session recovery behavior if implemented

# Output Format

Organize your findings into a single, self-contained technical specification using the following structure:

**1. Session Establishment**
- **Observed Behavior:** Step-by-step technical explanation of the sequential authentication exchange between client and C2 server
- **Handshake Logic:** Language-neutral pseudocode demonstrating how to format, encrypt, transmit the login payload, read and parse the server response, and validate session establishment
- **Success/Failure Handling:** precise conditions that indicate successful authentication and the resulting behavior, as well as failure conditions

**2. Cryptography**
- **Observed Behavior:** How the binary processes incoming and outgoing network traffic, including when and where encryption/decryption is applied within the communication flow.
- **Specification:** Exact algorithm names, parameters, mathematical operations, and keys required to decrypt incoming traffic
- **Decryption Routine:** Language-neutral pseudocode describing the complete decoding/decryption process, including keys, constants, algorithms, and operations.

**3. Main Command Loop**
- **Observed Behavior:** Step-by-step description of the command processing loop, from receiving network data through command execution
- **Protocol Specification:** Message format, framing, payload layout, opcode definitions, command parameters, attack specifications, and dynamic command registration (if implemented)
- **Message Processing Logic:** Language-neutral pseudocode demonstrating packet reception, decryption, parsing, opcode dispatch, and execution flow

**4. ACKs & Keepalives**
- **Observed Behavior:** The exact feedback transmission routine during command processing and normal operation
- **Response Packet Formats:** Exact structure of acknowledgments, execution status responses, heartbeat/keepalive packets, and status reports transmitted to the C2
- **Feedback Logic:** Language-neutral pseudocode demonstrating when and how acknowledgments, keepalives, and status updates are generated and transmitted

## Output Delivery

Save your completed analysis to a file named `communication_specification.md` (using the tool `write_file`).

The file should be self-contained and ready for immediate use by a developer without access to the original binary.

# Key Requirements

* **Implementation-Ready:** Optimize output for direct reimplementation and assume the reader is a developer with no access to the original binary.
* **Empirical Accuracy:** Strictly separate confirmed observations from inference or assumptions. Include all protocol constants and values (no generalizations; use actual captured configurations).
* **Analysis Gaps:** Explicitly document any parameters or behaviors within the communication layer that could not be determined, verified, or observed, noting the reason for each gap.
* **Zero Context:** Avoid security commentary, threat intelligence context, or conceptual explanations. Focus strictly on the technical protocol specification.