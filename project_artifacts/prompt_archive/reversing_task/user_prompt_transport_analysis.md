# Task

Your task is to extract, analyze, and document the **Transport Layer** from a malware sample belonging to the {{malware_family}} botnet family.

The objective is to provide a complete, implementation-ready technical specification of the malware's **C2 Infrastructure** retrieval and **Transport Initialization** with C2 server.

This includes how it locates and reaches its command-and-control servers, as well as all retrieval mechanisms and any obfuscation or encryption routines used to store, reconstruct, or decode C2-related configuration.

If a string table is present, briefly document its decoding mechanism, structure and content.

Focus on these components, explaining every mechanism directly related to them. Do not investigate or document any other functionality unless it is required to explain the C2 retrieval process or the connection phase.

The malware sample is already loaded and open in Ghidra. Perform all reverse engineering and analysis using Ghidra's tools. The sandbox environment is isolated from the malware file, do not attempt to access the malware from there.

{{malware_guide}}

# Required Analysis

**1. C2 Retrieval Mechanism**

Document exactly how the binary obtains the C2 server address (IP/hostname) and port. For each retrieval method present, provide:
- **How it works:** Step-by-step technical explanation of the retrieval or derivation process
- **Exact values & offsets:** Hardcoded strings, hex constants, memory offsets, encryption keys, seeds, and any intermediate values used to derive the C2 address and port
- **Retrieval logic:** Language-neutral pseudocode demonstrating the extraction, decryption, derivation, or resolution process
- **DNS logic:** If DNS resolution is involved, document the explicit DNS queries, domain construction, or resolution behavior

Specify whether the C2 address and port are:
- Hardcoded (provide exact offsets and values)
- Obfuscated/encrypted (provide the complete decryption/deobfuscation routine)
- Derived via Domain Generation Algorithm (document the algorithm and seed values)
- Obtained through any other mechanism

**2. String Table (if present)**

- **Check for presence:** Confirm whether an encoded string table exists
- **Cipher algorithm:** Determine which cipher or encoding scheme protects the strings
- **Content:** Decrypt and document the actual string table contents
- **Decrypt logic:** Provide the complete decryption routine (keys, algorithms, operations)

**3. Network & Connection Layer:**

Document the transport mechanism and connection lifecycle:
- **Protocol:** Identify the protocol(s) used (TCP, UDP, raw sockets, HTTP, HTTPS, or custom)
- **Initialization:** Connection establishment sequence, including socket creation, configuration, and all relevant connection parameters
- **Reconnection strategy:** Initial failure behavior, backoff algorithm, retry intervals, and maximum retry attempts

# Output Format

Organize your findings into a single, self-contained technical specification using the following structure:

**1. C2 Infrastructure Retrieval**
- **Observed Behavior:** Step-by-step technical explanation of how the binary resolves or extracts the C2 IP/hostname and port
- **Recovered C2 Address(es) & Port(s):** The final IP/hostname and port values obtained through analysis.
- **Retrieval Logic:** language-neutral pseudocode demonstrating the extraction or derivation process

**2. Transport Initialization**
- **Observed Behavior:** The exact socket creation and connection sequence observed during analysis
- **Network Parameters:** Protocol, socket options, default timeouts (connection/read/write), and any additional configuration
- **Connection Logic:** Language-neutral pseudocode demonstrating connection initialization.

**3. String Table Analysis (if applicable)**
- **Observed Behavior:** How the binary locates, decrypts, and accesses the string table during execution.
- **Decryption Routine:** Language-neutral pseudocode describing the complete decoding/decryption process, including keys, constants, algorithms, and operations.
- **Recovered Strings:** All recovered entries, indicating the purpose of each string where identifiable.

## Output Delivery

Save your completed analysis to a file named `transport_specification.md` (using the tool `write_file`).

The file should be self-contained and ready for immediate use by a developer without access to the original binary.

# Key Requirements

* **Implementation-Ready:** Optimize output for direct reimplementation and assume the reader is a developer with no access to the original binary.
* **Empirical Accuracy:** Strictly separate confirmed observations from inference or assumptions. Include all protocol constants and values (no generalizations; use actual captured configurations).
* **Analysis Gaps:** Explicitly document any parameters or behaviors within the transport layer that could not be determined, verified, or observed, noting the reason for each gap.
* **Zero Context:** Avoid security commentary, threat intelligence context, or conceptual explanations. Focus strictly on the technical protocol specification.