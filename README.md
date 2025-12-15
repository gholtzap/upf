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

# Not implemented Features
## 1. Core Protocol Support

### 1.1 PFCP (N4 Interface - UPF to SMF)
**Purpose:** Control plane communication with SMF

#### 1.1.5 PFCP Session Modification
- Session Modification Request/Response parsing
- Update PDR IE
- Update FAR IE
- Session state updates

#### 1.1.6 PFCP Session Deletion
- Session Deletion Request/Response parsing
- Session cleanup and resource release
- Usage reporting IEs

#### 1.1.7 Essential Information Elements
- PDR (Packet Detection Rule) encoding/decoding
- FAR (Forwarding Action Rule) encoding/decoding
- F-SEID (Session Endpoint Identifier)
- UE IP Address
- Network Instance
- QFI (QoS Flow Identifier)
- Apply Action (Forward/Drop/Buffer)

### 1.2 GTP-U Protocol Foundation
#### 1.2.4 GTP-U Error Indication
- Error Indication message generation
- Peer address information
- Tunnel endpoint identifier handling

#### 1.2.5 GTP-U End Marker
- End Marker message parsing
- Path switch support

#### 1.2.6 N6 Interface Handler
- Raw socket or TAP interface setup
- Plain IP packet forwarding to internet
- Encapsulation logic for downlink
- Integration with session store

### 1.3 Basic IP Routing
- IPv4 packet forwarding
- IPv6 packet forwarding
- Simple routing table lookup
- ARP resolution for next-hop

## 2. Packet Processing (Simplified)

### 2.1 Receive Packets
- Raw socket or libpcap for packet I/O
- Read packets from network interfaces
- Parse Ethernet/IP/UDP/GTP headers

### 2.2 Classify Packets
**Uplink (from UE):**
- Match on GTP-U TEID from N3 interface
- Look up session by TEID
- Apply matching PDR rules

**Downlink (to UE):**
- Match on destination IP address from N6 interface
- Look up session by UE IP
- Apply matching PDR rules

### 2.3 Forward Packets
**Based on FAR action:**
- Forward to N6: Strip GTP header, send to internet
- Forward to N3: Add GTP header, send to base station
- Drop: Discard packet
- Buffer: Store temporarily (basic queue)

### 2.4 Basic QoS
- Simple priority queue (2 levels: high priority, normal)
- Basic rate limiting per session (token bucket)
- No fancy scheduling needed initially

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
