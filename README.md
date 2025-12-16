# UPF

# Implemented features
## 7. Configuration
- YAML-based configuration file
- Support for N4, N3, N6 interface configuration
- UPF Node ID configuration
- Log level configuration
- Configuration validation

## 8. Logging
- Console output with env_logger
- Configurable log levels (ERROR, WARN, INFO, DEBUG)
- Logging of application initialization

## 9. Data Structures
- Core type definitions (SEID, TEID, PDRID, FARID)
- PDR (Packet Detection Rule) structure
- FAR (Forwarding Action Rule) structure
- Session structure with statistics
- Thread-safe session state design

## 10. Minimal Dependencies
- Rust project with Cargo
- tokio for async runtime
- serde for serialization
- bytes for byte buffer handling
- log and env_logger for logging
- thiserror for error handling
- socket2 for raw sockets
- pnet for packet parsing
- serde_yaml for config parsing
- clap for command line arguments
- anyhow for error handling

## 11. PFCP Protocol Infrastructure
- PFCP message header parsing and encoding (version, message type, length, SEID)
- Sequence number management for requests/responses
- UDP socket on N4 interface (port 8805)
- Basic message framing and validation
- Information Element (IE) encoding/decoding framework
- Message type enumeration (Heartbeat, Association Setup, Session Management)
- Cause value enumeration for response messages
- Node ID types (IPv4, IPv6, FQDN)

## 12. PFCP Association Setup
- Association Setup Request/Response parsing
- Node ID Information Element
- Recovery Time Stamp Information Element
- Association state management

## 13. PFCP Heartbeat
- Heartbeat Request/Response parsing
- Recovery Time Stamp handling
- Connection health monitoring

## 14. F-SEID Information Element
- IE type and structure definition
- IPv4 and IPv6 support
- SEID encoding/decoding
- Parse and encode functions
- Support for dual-stack (IPv4 + IPv6)
- Full test coverage

## 15. UE IP Address Information Element
- IE type and structure definition
- IPv4 and IPv6 address allocation
- Parse and encode functions
- Support for dual-stack (IPv4 + IPv6)
- Full test coverage

## 16. Network Instance Information Element
- IE type and structure definition
- APN/DNN string encoding
- Parse and encode functions
- Full test coverage

## 17. PDR ID Information Element
- IE type and structure definition
- PDR ID encoding/decoding (u16)
- Parse and encode functions
- Full test coverage

## 18. FAR ID Information Element
- IE type and structure definition
- FAR ID encoding/decoding (u32)
- Parse and encode functions
- Full test coverage

## 19. Precedence Information Element
- IE type and structure definition
- Precedence value encoding/decoding (u32)
- Parse and encode functions
- Full test coverage

## 20. Source Interface Information Element
- IE type and structure definition
- Interface type enumeration (Access, Core, SGi-LAN/N6-LAN, CP-Function)
- Parse and encode functions
- Full test coverage

## 21. Destination Interface Information Element
- IE type and structure definition
- Interface type enumeration (Access, Core, SGi-LAN/N6-LAN, CP-Function, LI Function)
- Parse and encode functions
- Full test coverage

## 22. Apply Action Information Element
- IE type and structure definition
- Action flags (DROP, FORWARD, BUFFER, NOCP, DUPL)
- Parse and encode functions
- Full test coverage

## 23. PDI (Packet Detection Information) Information Element
- IE type and structure definition
- Grouped IE containing Source Interface, Network Instance, UE IP Address
- Parse and encode functions
- Full test coverage

## 24. Create PDR Information Element
- IE type and structure definition
- Grouped IE containing PDR ID, Precedence, PDI, and FAR ID
- Parse and encode functions
- Full test coverage

## 25. Create FAR Information Element
- IE type and structure definition
- Grouped IE containing FAR ID, Apply Action, and Destination Interface
- Parse and encode functions
- Full test coverage

## 26. PFCP Session Establishment
- Session Establishment Request message parsing
- Session Establishment Response message generation
- Session store with thread-safe HashMap
- SEID to Session mapping
- PDR and FAR association with sessions
- Integration with PfcpServer
- Full test coverage

## 27. GTP-U Header Structure
- GTP-U header parsing (version, PT, E, S, PN flags)
- Message type enumeration (Echo Request/Response, Error Indication, G-PDU, End Marker)
- TEID extraction and encoding
- Sequence number handling
- Extension header support structure
- Full test coverage

## 28. GTP-U Echo Request/Response
- Echo Request message creation
- Echo Response message generation
- Recovery counter management with atomic operations
- Sequence number preservation in responses
- Health check mechanism support
- Full test coverage

## 29. GTP-U G-PDU Handling
- G-PDU message parsing
- Payload extraction
- TEID to session lookup support
- Extension header parsing (QFI from PDU Session Container)
- QFI type definition
- SessionManager TEID-based lookup
- Full test coverage

## 30. N3 Interface Handler
- UDP socket on port 2152
- Receive GTP-U packets from RAN
- GTP-U Echo Request/Response handling
- G-PDU decapsulation logic
- Integration with session store for TEID lookup
- Session statistics updates (uplink packets/bytes)
- Concurrent operation with PFCP server

## 31. N6 Interface Handler
- Channel-based communication between N3 and N6 handlers
- Uplink packet forwarding (N3 -> N6)
- IP packet parsing and logging (IPv4 and IPv6)
- Destination IP extraction
- Integration with session manager
- Downlink packet encapsulation support (N6 -> N3)
- Session lookup by UE IP address
- GTP-U encapsulation for downlink traffic
- Session statistics updates (downlink packets/bytes)
- Concurrent operation with N3 and PFCP handlers

## 32. Usage Report Information Elements
- Volume Measurement IE (total, uplink, downlink volumes)
- Duration Measurement IE
- Usage Report SDR (Session Deletion Response) grouped IE
- IE encoding and decoding with proper flag handling
- Full test coverage

## 33. PFCP Session Deletion
- Session Deletion Request message parsing
- Session Deletion Response message generation
- Session cleanup and resource release
- Usage reporting in deletion response
- Volume statistics (total, uplink, downlink bytes)
- Duration statistics (session lifetime)
- Integration with PfcpServer
- Session context validation
- Error handling for missing sessions

## 34. PFCP Session Modification
- Session Modification Request message parsing
- Session Modification Response message generation
- Update PDR Information Element
- Update FAR Information Element
- Session state updates for existing PDRs
- Session state updates for existing FARs
- Dynamic rule modification support
- Integration with PfcpServer
- Session context validation
- Error handling for missing sessions

## 35. PDR Matching Engine
- Packet classifier module for PDR matching
- Match packets against PDR rules based on source interface
- Match uplink packets by TEID (Access interface)
- Match downlink packets by UE IP address (Core interface)
- Precedence-based PDR selection (highest precedence wins)
- Return matched PDR and associated FAR ID
- Full test coverage for all matching scenarios

## 36. FAR Application Engine
- FAR lookup by ID from session's FAR list
- Apply Forward action (extract forwarding parameters)
- Apply Drop action (discard packet)
- Apply Buffer action (queue packet for future implementation)
- Forwarding decision enumeration (Forward/Drop/Buffer)
- ForwardingInfo structure with destination interface, TEID, and remote address
- Integrated lookup and apply functionality
- Full test coverage for all actions and edge cases

## 37. Uplink Packet Processing Integration
- PDR matching integrated into N3 handler for uplink traffic
- PacketContext creation with source interface (Access) and TEID
- FAR actions applied for matched packets (Forward/Drop/Buffer)
- Forward action: packets forwarded to N6 interface with Core destination
- Drop action: packets dropped and logged
- Buffer action: logged as not yet implemented, packets dropped
- No matching PDR: packets dropped and logged with warning
- Session statistics updated only for successfully forwarded packets
- Detailed logging of PDR/FAR matching and forwarding decisions

## 38. N6 Downlink Reception
- UDP socket on N6 interface for downlink packet reception
- Parse IP headers to extract destination UE IP address (IPv4 and IPv6)
- Session lookup by UE IP address
- Concurrent reception with uplink packet processing
- Integration with session manager

## 39. Downlink Packet Processing Integration
- PDR matching integrated into N6 downlink path
- PacketContext creation with source interface (Core) and destination UE IP
- FAR actions applied for downlink traffic (Forward/Drop/Buffer)
- Forward action: GTP-U encapsulation and transmission to RAN with correct TEID
- Drop action: packets dropped and logged
- Buffer action: logged as not yet implemented, packets dropped
- No matching PDR: packets dropped and logged with warning
- Session statistics updated for downlink packets (packets/bytes)
- Detailed logging of PDR/FAR matching and forwarding decisions
- Complete bidirectional packet flow (uplink and downlink)

## 40. N6 Uplink Forwarding to Data Network
- Raw socket creation for IPv4 and IPv6 packet forwarding
- Platform-specific implementations (Unix/Linux and Windows support)
- IP_HDRINCL/IPV6_HDRINCL socket options for custom IP header support
- Destination IP parsing from IP packet headers (IPv4 and IPv6)
- Actual packet transmission to internet/data network via raw sockets
- Comprehensive error handling with fallback for unavailable raw sockets
- Graceful degradation when raw socket creation fails
- Detailed logging of forwarding operations and errors
- Cross-platform compatibility with conditional compilation

## 41. GTP-U Error Indication
- Error Indication message generation
- Tunnel Endpoint Identifier Data I IE encoding/decoding
- GTP-U Peer Address IE encoding/decoding (IPv4 and IPv6)
- Automatic Error Indication transmission for unknown TEIDs
- Integration with N3 handler
- Full test coverage for IPv4 and IPv6 peer addresses
- Message parsing and validation

## 42. GTP-U End Marker
- End Marker message creation and parsing
- Message validation for End Marker
- Support for sequence number in End Marker messages
- Path switch indication handling
- Integration with N3 interface handler
- End Marker reception logging and processing
- Full test coverage for End Marker functionality

## 43. QoS Profile Management
- QFI to priority level mapping (High, Normal)
- QoS profile structure with bitrate limits (max and guaranteed for uplink/downlink)
- Default QoS profiles for standard QFI values (1, 5, 9)
- QosProfileManager for centralized QoS profile lookup
- YAML configuration support for custom QoS profiles
- Integration with SessionManager for QoS-aware operations
- Full test coverage for QoS profile management

## 44. Priority Queue Implementation
- Two-level priority queue (high priority, normal)
- Thread-safe queue data structures using Arc and Mutex
- Priority-based dequeue logic (high priority packets dequeued first)
- Queue size limits per priority level (configurable)
- Overflow handling with QueueFull error reporting
- FIFO ordering within each priority level
- Queue statistics (len, high_priority_len, normal_priority_len)
- Clear operation for queue reset
- Full test coverage for all queue operations

# Not implemented Features
## 1. Core Protocol Support

### 1.1 PFCP (N4 Interface - UPF to SMF)
**Purpose:** Control plane communication with SMF

#### 1.1.6 Essential Information Elements
- PDR (Packet Detection Rule) encoding/decoding
- FAR (Forwarding Action Rule) encoding/decoding
- F-SEID (Session Endpoint Identifier)
- UE IP Address
- Network Instance
- QFI (QoS Flow Identifier)
- Apply Action (Forward/Drop/Buffer)

### 1.2 GTP-U Protocol Foundation

### 1.3 Basic IP Routing
- IPv4 packet forwarding
- IPv6 packet forwarding
- Simple routing table lookup
- ARP resolution for next-hop

## 2. Packet Processing (Simplified)

### 2.5 Basic QoS

#### 2.5.3 Token Bucket Rate Limiting
- Per-session token bucket implementation
- Configurable rate and burst size
- Token bucket state tracking
- Rate limiting enforcement on packet forwarding

#### 2.5.4 QoS-Aware Packet Forwarding
- QFI extraction from GTP-U extension headers
- QFI-based QoS profile lookup
- Priority queue enqueue/dequeue in forwarding path
- Token bucket check before forwarding
- Integration with N6 packet forwarding

## 3. Session Management

### 3.1 Session State
**Store for each session:**
- Session ID (F-SEID)
- UE IP address
- N3 TEID (uplink tunnel)
- N6 TEID (downlink tunnel, if needed)
- RAN IP address (where to send downlink packets)
- List of PDRs for this session
- List of FARs for this session
- Session status (active/inactive)

### 3.2 Session Operations
- Create session (on PFCP Session Establishment)
- Update session (on PFCP Session Modification)
- Delete session (on PFCP Session Deletion)
- Store in simple HashMap or similar

## 4. Network Interfaces

### 4.1 Required Interfaces
**N4 (PFCP):**
- UDP socket on port 8805
- Handle PFCP messages
- Send/receive from SMF

**N3 (GTP-U from RAN):**
- UDP socket on port 2152
- Receive GTP-U packets from base stations
- Send GTP-U packets to base stations

**N6 (Internet/DN):**
- Raw IP or TAP interface
- Forward plain IP packets
- Interface to internet or data network

### 4.2 Basic Network Config
- Assign IP addresses to each interface
- Simple routing: "packets from N3 go to N6, packets from N6 go to N3"
- No complex routing protocols needed

## 5. Essential Features Only

### 5.1 IP Address Management
**Simple approach:**
- SMF tells UPF what IP address to use for each UE
- Store mapping: UE IP → Session
- No need for DHCP or complex allocation
- Static pool if you need to allocate yourself (just a list of IPs)

### 5.2 PDU Session Types
**Support:**
- IPv4 sessions (most common)
- IPv6 sessions (if needed)
- Can ignore Ethernet and Unstructured initially

### 5.3 Minimal Statistics
**Per session, track:**
- Uplink bytes
- Downlink bytes
- Uplink packets
- Downlink packets
- Last activity timestamp

**Report when:**
- Session is deleted
- SMF requests it (Session Report)

## 6. Error Handling

### 6.1 Basic Error Handling
- Log errors to console/file
- Send GTP-U Error Indication if can't deliver packet
- Send PFCP error responses for invalid requests
- Don't crash on malformed packets
- Simple retry for PFCP messages

### 6.2 Failure Scenarios
- Unknown TEID: Drop packet, send Error Indication
- No matching PDR: Drop packet
- Session not found: Send PFCP error response
- Interface down: Log error, drop packets

## 18. Critical 3GPP Specs to Read

**Must read:**
- TS 29.244 - PFCP protocol (focus on sections 7.4-7.5 for messages)
- TS 29.281 - GTP-U protocol (focus on packet format)

**Reference as needed:**
- TS 23.501 - 5G System Architecture (overview)
- TS 29.244 Section 8 - Information Elements (PDR, FAR definitions)

**Can ignore initially:**
- Most other specs (they're for advanced features)
