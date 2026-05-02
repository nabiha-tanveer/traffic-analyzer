# NetWatch - Network Traffic Analyzer

A real-time network traffic analyzer built with C++ backend and web-based frontend.

## Features
- Real-time packet capture using Npcap
- Protocol detection (TCP, UDP, ICMP, IPv4, IPv6)
- Service identification (HTTP, HTTPS, DNS, SSH, etc.)
- Web-based dashboard accessible via browser
- Live filtering by Protocol, Source IP, Destination IP
- Activity log with timestamps
- Dark/Light mode toggle
- Wireshark-style color coded rows

## Technology Stack

### Backend (C++)
- **Language:** C++17
- **Packet Capture:** Npcap SDK (libpcap)
- **Server:** Custom HTTP server using WinSock2
- **Threading:** std::thread + std::mutex
- **Data Structure:** Custom Ring Buffer

### Frontend (HTML/CSS/JS)
- Vanilla JavaScript (no frameworks)
- Fetch API for REST communication
- Responsive web design

## Prerequisites
- Windows 10/11
- [Npcap](https://npcap.com) driver installed
- Run as Administrator

## How to Run

1. Install [Npcap](https://npcap.com/dist/npcap-1.79.exe)
2. Download `networktraffic.exe`
3. Run as Administrator:
```cmd
networktraffic.exe
```
4. Open browser: `http://localhost:8080`
5. Select network interface → Click Start

## How to Build from Source

### Requirements
- MinGW-w64 / MSYS2
- Npcap SDK

### Build Command
```bash
g++ -O2 -std=c++17 -o networktraffic.exe SRC/main.cpp \
    -I"C:/npcap-sdk/Include" \
    "C:/npcap-sdk/Lib/x64/wpcap.lib" \
    "C:/npcap-sdk/Lib/x64/Packet.lib" \
    -lws2_32 -lpthread
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/interfaces` | GET | List network interfaces |
| `/api/begin?device=X` | GET | Start packet capture |
| `/api/halt` | GET | Stop packet capture |
| `/api/flows` | GET | Get captured packets |
| `/api/metrics` | GET | Get statistics |
| `/api/state` | GET | Get capture status |

## Project Structure# traffic-analyzer
network-traffic-analyzer/
├── SRC/
│   └── main.cpp        # C++ backend server + packet capture
├── web/
│   ├── index.html      # Frontend UI
│   ├── styles.css      # Styling
│   └── app.js          # Frontend JavaScript logic
└── README.md
