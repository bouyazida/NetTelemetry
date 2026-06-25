# NetTelemetry — C++ Network Monitoring Tool

A real-time network telemetry application that captures live packet data, computes traffic metrics, resolves hostnames, and stores everything in a SQL Server database.

---

## Features

- **Live packet capture** using Npcap / libpcap
- **Traffic metrics**: Bytes per second (BPS), Packets per second (PPS), latency estimation
- **Reverse DNS resolution** via `gethostbyaddr()`
- **SQL Server integration** via ODBC for persistent storage of captured sessions

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | C++17 |
| Packet Capture | Npcap / libpcap |
| Database | SQL Server (ODBC) |
| DNS Resolution | Winsock2 (`gethostbyaddr`) |
| Platform | Windows |

---

## Prerequisites

- Windows 10/11
- [Npcap](https://npcap.com/) installed (with WinPcap compatibility mode)
- SQL Server (local or remote instance)
- ODBC Driver for SQL Server
- Visual Studio 2019+ or MinGW with C++17 support

---

## Build

```bash
# With MSVC (Visual Studio Developer Command Prompt)
cl /std:c++17 main.cpp /link wpcap.lib ws2_32.lib odbc32.lib

# Or with g++ (MinGW)
g++ -std=c++17 main.cpp -lwpcap -lws2_32 -lodbc32 -o NetTelemetry.exe
```

---

## Database Setup

Run the following SQL to create the required table:

```sql
CREATE TABLE PacketLog (
    id          INT IDENTITY PRIMARY KEY,
    timestamp   DATETIME DEFAULT GETDATE(),
    src_ip      VARCHAR(45),
    dst_ip      VARCHAR(45),
    hostname    VARCHAR(255),
    protocol    TINYINT,
    packet_size INT,
    bps         FLOAT,
    pps         FLOAT
);
```

Update the ODBC connection string in the source to match your server name and database.

---

## Usage

```bash
# Run as Administrator (required for raw packet capture)
NetTelemetry.exe
```

Select the network interface from the listed adapters, then the tool begins capturing and logging in real time.

---

## Project Structure

```
NetTelemetry/
├── main.cpp          # Entry point, interface selection
├── capture.cpp/.h    # Packet capture logic (Npcap)
├── metrics.cpp/.h    # BPS / PPS / latency computation
├── dns.cpp/.h        # Reverse DNS resolution
├── db.cpp/.h         # ODBC / SQL Server interface
└── README.md
```

*(Adjust to match your actual file layout)*

---

## Author

**Boubaker** — IoT Engineering Student, ISITCOM Hammam Sousse  
Built as a summer independent project — 2026 #NetTelemetry
