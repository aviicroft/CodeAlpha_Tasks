# Network Architecture & Protocol Analysis

## OSI Model Overview

The Advanced Network Traffic Analyzer monitors traffic across multiple layers of the OSI (Open Systems Interconnection) model:

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 7: APPLICATION                 (DNS, HTTP, HTTPS)     │
├─────────────────────────────────────────────────────────────┤
│ Layer 6: PRESENTATION                (Encryption, etc.)     │
├─────────────────────────────────────────────────────────────┤
│ Layer 5: SESSION                     (Session Management)   │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: TRANSPORT                   (TCP, UDP)             │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: NETWORK                     (IP, ICMP, ARP)        │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: DATA LINK                   (Ethernet)             │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: PHYSICAL                    (Network Interface)    │
└─────────────────────────────────────────────────────────────┘
```

## Supported Protocols

### Layer 2 - Data Link Layer

#### Ethernet
- **Header Size:** 14 bytes
- **Fields Captured:**
  - Source MAC Address (6 bytes)
  - Destination MAC Address (6 bytes)
  - EtherType (2 bytes) - Identifies protocol
- **Use Cases:** LAN communication, MAC address tracking
- **Threats Detected:** MAC spoofing patterns

### Layer 3 - Network Layer

#### IPv4
- **Header Size:** 20 bytes (minimum)
- **Key Fields:**
  - Source IP: 4 bytes
  - Destination IP: 4 bytes
  - TTL (Time To Live): 1 byte
  - Protocol: 1 byte (indicates Layer 4 protocol)
  - Flags: Control flags (DF, MF, Reserved)
  - Fragment Offset: Reassembly information
- **Analysis:**
  - Host identification
  - Routing analysis
  - Geographic location mapping
  - Fragmentation detection

#### ICMP (Internet Control Message Protocol)
- **Purpose:** Network diagnostics and error reporting
- **Common Types:**
  - Type 8: Echo Request (Ping)
  - Type 0: Echo Reply
  - Type 11: Time Exceeded
  - Type 3: Destination Unreachable
- **Use Cases:**
  - Network reachability tests
  - Latency measurement
  - Traceroute operations
- **Threats:** ICMP flood attacks

#### ARP (Address Resolution Protocol)
- **Purpose:** Maps IP addresses to MAC addresses
- **Format:**
  - Request: "Who has IP X.X.X.X?"
  - Reply: "I have IP X.X.X.X, my MAC is YY:YY:YY:YY:YY:YY"
- **Threats Detected:**
  - ARP Spoofing: Attacker maps their MAC to someone else's IP
  - ARP Flooding: Excessive ARP requests
  - Gratuitous ARP abuse: Unsolicited ARP replies

### Layer 4 - Transport Layer

#### TCP (Transmission Control Protocol)
- **Connection-Oriented:** Establishes connection before data transfer
- **Three-Way Handshake:**
  ```
  Client                    Server
    │ SYN (seq=x)           │
    ├──────────────────────>│
    │                  SYN-ACK (seq=y, ack=x+1)
    │<──────────────────────┤
    │ ACK (seq=x+1, ack=y+1)│
    ├──────────────────────>│
    │                   Connection Established
  ```
- **Flags:**
  - SYN: Synchronize sequence numbers
  - ACK: Acknowledgment
  - FIN: Finish (graceful close)
  - RST: Reset (forceful close)
  - PSH: Push (send data immediately)
  - URG: Urgent pointer
- **Ports Tracked:** Well-known (0-1023), Registered (1024-49151), Dynamic (49152-65535)

#### UDP (User Datagram Protocol)
- **Connectionless:** No handshake required
- **Characteristics:**
  - Low overhead
  - No guaranteed delivery
  - No ordering guarantee
  - Faster than TCP
- **Common Applications:**
  - DNS (Port 53)
  - DHCP (Ports 67-68)
  - NTP (Port 123)
  - Video streaming
  - Online gaming

### Layer 7 - Application Layer

#### DNS (Domain Name System)
- **Purpose:** Translates domain names to IP addresses
- **Default Port:** 53 (both TCP and UDP)
- **Query Types:**
  - A: IPv4 address
  - AAAA: IPv6 address
  - CNAME: Canonical name
  - MX: Mail exchange
  - NS: Name server
  - TXT: Text record
- **Analysis Performed:**
  - Query pattern analysis
  - Domain reputation checking
  - DNS tunneling detection
  - Malware C2 communication detection
- **Threats Detected:**
  - DNS Flooding: Excessive queries
  - DNS Spoofing: Fake responses
  - DNS Exfiltration: Data stealing via DNS

#### HTTP/HTTPS
- **HTTP Port:** 80 (unencrypted)
- **HTTPS Port:** 443 (encrypted with TLS/SSL)
- **Captured Information:**
  - HTTP Method: GET, POST, PUT, DELETE, etc.
  - URI/Path: Resource being accessed
  - Host: Domain name
  - User-Agent: Client information
  - Referrer: Page origin
- **Security Considerations:**
  - Always use HTTPS for sensitive data
  - HTTP traffic can be sniffed
  - Certificate validation important for HTTPS

## Packet Structure Example

### Complete TCP/IP Stack for HTTP Request

```
┌─────────────────────────────────────────────────────┐
│ ETHERNET FRAME                                      │
├─────────────────────────────────────────────────────┤
│ Dest MAC: AA:BB:CC:DD:EE:FF                        │
│ Src MAC:  11:22:33:44:55:66                        │
│ Type: 0x0800 (IPv4)                                │
├─────────────────────────────────────────────────────┤
│ IPV4 HEADER                                         │
├─────────────────────────────────────────────────────┤
│ Version: 4, Header Length: 20 bytes                │
│ TTL: 64                                            │
│ Protocol: 6 (TCP)                                  │
│ Source: 192.168.1.100                              │
│ Dest: 93.184.216.34                                │
├─────────────────────────────────────────────────────┤
│ TCP HEADER                                          │
├─────────────────────────────────────────────────────┤
│ Source Port: 54321                                 │
│ Dest Port: 80                                      │
│ Sequence: 1000000                                  │
│ Ack: 2000000                                       │
│ Flags: PSH, ACK                                    │
│ Window: 65535                                      │
├─────────────────────────────────────────────────────┤
│ HTTP PAYLOAD                                        │
├─────────────────────────────────────────────────────┤
│ GET / HTTP/1.1                                     │
│ Host: example.com                                  │
│ User-Agent: Mozilla/5.0                           │
│ Connection: close                                  │
└─────────────────────────────────────────────────────┘
```

## Network Flow Analysis

### TCP Connection Lifecycle

```
CLIENT                                    SERVER

ESTABLISHED ─────────────────────────────────────>  ESTABLISHED
(SYN sent)        
              <───────────────────────────────────  ESTABLISHED
           (SYN-ACK received)
              
              (DATA TRANSFER)
              ───────────────────────────────────>
              <───────────────────────────────────
              
              (GRACEFUL CLOSE)
              ───────────────────────────────────>
                     (FIN sent)
              <───────────────────────────────────
              (FIN received)
              
              ───────────────────────────────────>
                   (ACK sent)
              
CLOSED                                            CLOSED
```

## Analysis Algorithms

### Port Scanning Detection
- **Algorithm:** Threshold-based detection
- **Detection Method:**
  1. Track TCP connections from each source IP
  2. Count unique destination ports in time window (default: 30 seconds)
  3. Alert if unique ports > threshold (default: 20)
  4. Use flags to distinguish normal behavior from scanning

### ARP Spoofing Detection
- **Algorithm:** MAC/IP relationship tracking
- **Detection Method:**
  1. Maintain mapping of IP → MAC address
  2. Track responses for each IP
  3. Alert if single IP has multiple MAC addresses
  4. Flag gratuitous ARP from unexpected sources

### DNS Flooding Detection
- **Algorithm:** Query rate monitoring
- **Detection Method:**
  1. Track DNS queries per source IP
  2. Count queries in time window (default: 10 seconds)
  3. Alert if query count > threshold (default: 50 queries)
  4. Track repeated domain queries

## Performance Considerations

### Packet Processing Pipeline

```
┌──────────────────┐
│ Raw Packet       │
│ (from network)   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Capture Filter   │
│ (protocol, IP)   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Packet Parser    │
│ (decode layers)  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Threat Analysis  │
│ (detect patterns)│
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Statistics       │
│ (aggregate data) │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Storage/Display  │
│ (save & show)    │
└──────────────────┘
```

### Memory Management
- **Circular Buffer:** Stores last N packets (configurable)
- **Default Max Packets:** 10,000
- **Average Memory per Packet:** ~500 bytes
- **Maximum Memory Usage:** ~5MB for default settings

## Common Ports Reference

| Port | Protocol | Service |
|------|----------|---------|
| 20 | TCP | FTP Data |
| 21 | TCP | FTP Control |
| 22 | TCP | SSH |
| 23 | TCP | Telnet |
| 25 | TCP | SMTP |
| 53 | TCP/UDP | DNS |
| 67 | UDP | DHCP Server |
| 68 | UDP | DHCP Client |
| 80 | TCP | HTTP |
| 110 | TCP | POP3 |
| 143 | TCP | IMAP |
| 443 | TCP | HTTPS |
| 465 | TCP | SMTPS |
| 587 | TCP | SMTP Alt |
| 993 | TCP | IMAPS |
| 995 | TCP | POP3S |
| 3306 | TCP | MySQL |
| 3389 | TCP | RDP |
| 5432 | TCP | PostgreSQL |
| 8080 | TCP | HTTP Alt |

---

**Last Updated:** 2024
**Version:** 1.0.0
