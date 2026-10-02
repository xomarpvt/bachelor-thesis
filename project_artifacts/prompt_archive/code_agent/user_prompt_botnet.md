# Task

Your task is to implement a botnet C2 communication module that accurately reproduces the communication behavior of the specified malware sample.

The implementation must be provided as a single, complete Python file that integrates seamlessly with the existing codebase architecture.

The primary focus of this task is recreating the malware's C2 transport and communication layer, including C2 connection handling, session establishment, and the command processing loop.

The implementation is intended strictly for defensive purposes; therefore, it will not include or perform any attack functionality, malicious behavior, or offensive capabilities.

# Reference Materials

## BotNetInterface

**Description**: The base interface that defines the required `connect()` and `sniff()` methods. These methods form the core contract of the implementation and their behavior must adhere exactly to the provided specification.

{{botnet_interface}}

## Specification Documents

**Description**: Specification documents outlining the connect phase structure, login/authentication logic, command receive loop, and heartbeat/ACK logic. Refer to this document to understand how these features work and how to accurately replicate their behavior in your implementation.

{{botnet_specification}}

## Template Implementation

**Description**: Reference Python implementation illustrating the existing architecture. It implements the `BotnetInterface` and exposes the `Botnet` class. Follow its patterns closely, including class structure, logging conventions, and constants.

{{botnet_template}}

## Message Classification

**Description**: Enumeration defining the supported botnet message categories used throughout the implementation. Each `MessageType` identifies the semantic purpose of a received message, allowing the client to dispatch handling logic consistently according to the protocol specification.

{{message_classification}}

# Technical Requirements

1. **`connect()` Function**
   - Retrieve the C2 endpoint (IP and port) from the configuration, or as specified in the documentation.
   - Establish a socket connection to the C2 server.
   - Implement the complete protocol initialization sequence, including any required handshake, authentication, registration, or login messages, exactly as defined by the protocol.
   - If the protocol requires client registration or fingerprinting, do not perform real host or system discovery.
     Instead, generate a consistent set of simulated victim attributes representing a plausible IoT device.

2. **`sniff()` Function**
   - Listen indefinitely for incoming commands from the C2
   - Apply stream preprocessing only if the protocol requires stream-level transformations.
   - Append received bytes to the internal buffer and extract complete protocol packets using the required packet framing logic.
   - Decode or decrypt packets only when required by the protocol.
   - Extract individual messages from decoded packets.
   - Determine the message type using protocol-specific indicators:
     - Identify server acknowledgement responses as `ACK`.
     - Identify server keepalive traffic as `HEARTBEAT`.
     - Identify attack instructions as `ATTACK`. If there is uncertainty between `ATTACK` and `COMMAND`, classify as `ATTACK`.
     - Use `COMMAND` only as a final fallback, when the message is confirmed not to be `ACK`, `HEARTBEAT`, or `ATTACK`.
   - Implement protocol-specific message handling through `handle_message()`:
     - Send message acknowledgments only when the protocol explicitly requires an ACK response.
     - Implement any required command responses or state updates.
     - Do not add implicit responses not defined by the protocol specification.
   - Delegate message parsing exclusively to `MessageParser.parse_message(timestamp: datetime, source_ip: str, data: bytes, message_type: MessageType)` (module `parser.py`).
   - Yield each parsed message returned by `MessageParser` as the output of the reception loop.
   - Maintain the C2 session according to protocol requirements, send heartbeat messages only when explicitly required by the protocol.
     Do not send unsolicited heartbeats or periodic traffic unless the protocol specification defines this behavior.

3. **Implementation Guidelines**
   - Implement only the `Botnet` class. Do not introduce functionality that belongs outside this class or duplicate responsibilities already handled by existing components.
   - Replace all template placeholders (C2 host, port, handshake payloads, authentication data, heartbeat messages, timeouts, and protocol constants) with values derived from the protocol documentation.
   - Follow the modular structure provided by the template:
     - Reuse the existing workflow and override only the methods required by the protocol.
     - Keep transport handling, packet processing, message classification, and parsing responsibilities separated.
     - Avoid implementing unrelated functionality or behaviors not required by the protocol specification.
   - Maintain the logging conventions established by the template for lifecycle events, debugging, and protocol processing.
   - Handle expected errors gracefully (e.g., connection failures, timeouts, malformed data) without unnecessary complexity.

# Output Format

Return a single, complete Python file that:
- Is fully implemented, ready for integration into the existing codebase, and requires no additional modifications before use
- Follows the exact template structure, coding patterns, and architectural conventions provided
- Adheres to the specified requirements and incorporates the relevant details from the provided specifications and reference materials