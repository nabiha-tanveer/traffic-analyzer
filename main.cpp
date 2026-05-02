#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <queue>
#include <map>
#include <array>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <ctime>
#include <cstring>
#include <algorithm>
#include <iomanip>
#include <condition_variable>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Packet.lib")

using namespace std;

// ============================================================================
// NETWORK PROTOCOL DEFINITIONS (Different naming convention)
// ============================================================================
#pragma pack(push, 1)
struct EthHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};

struct IPv4Hdr {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct IPv6Hdr {
    uint32_t ver_tc_fl;
    uint16_t payload_len;
    uint8_t next_hdr;
    uint8_t hop_limit;
    uint8_t saddr[16];
    uint8_t daddr[16];
};

struct TCPHdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_off;
    uint8_t flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct UDPHdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t check;
};

struct ICMPHdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
};
#pragma pack(pop)

// ============================================================================
// PACKET DATA STRUCTURE
// ============================================================================
struct NetPacket {
    string capture_time;
    string src_ip;
    string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    string proto;
    uint32_t pkt_size;
    string app_service;
};

// ============================================================================
// RING BUFFER FOR PACKET STORAGE (Different approach from vector)
// ============================================================================
class PacketRingBuffer {
private:
    vector<NetPacket> buffer_;
    size_t head_;
    size_t tail_;
    size_t count_;
    size_t capacity_;
    mutable mutex mtx_;

public:
    explicit PacketRingBuffer(size_t size = 5000) 
        : buffer_(size), head_(0), tail_(0), count_(0), capacity_(size) {}

    void push(const NetPacket& pkt) {
        lock_guard<mutex> lock(mtx_);
        buffer_[tail_] = pkt;
        tail_ = (tail_ + 1) % capacity_;
        if (count_ < capacity_) {
            count_++;
        } else {
            head_ = (head_ + 1) % capacity_;
        }
    }

    vector<NetPacket> get_all() const {
        lock_guard<mutex> lock(mtx_);
        vector<NetPacket> result;
        result.reserve(count_);
        for (size_t i = 0; i < count_; i++) {
            result.push_back(buffer_[(head_ + i) % capacity_]);
        }
        return result;
    }

    void clear() {
        lock_guard<mutex> lock(mtx_);
        head_ = tail_ = count_ = 0;
    }

    size_t size() const {
        lock_guard<mutex> lock(mtx_);
        return count_;
    }
};

// ============================================================================
// GLOBAL STATE
// ============================================================================
PacketRingBuffer g_packet_buffer;
atomic<bool> g_is_running{false};
atomic<bool> g_should_stop{false};
atomic<uint64_t> g_byte_count{0};
map<string, atomic<uint64_t>> g_proto_stats;
map<string, atomic<uint64_t>> g_service_stats;
mutex g_stats_mtx;
pcap_t* g_pcap_handle = nullptr;
thread g_capture_thread;

// ============================================================================
// UTILITY FUNCTIONS (Different implementations)
// ============================================================================
string current_timestamp() {
    auto now = chrono::system_clock::now();
    time_t tt = chrono::system_clock::to_time_t(now);
    tm local_tm;
    localtime_s(&local_tm, &tt);
    char buf[32];
    strftime(buf, sizeof(buf), "%H:%M:%S", &local_tm);
    return string(buf);
}

string ipv4_to_string(uint32_t ip) {
    array<char, INET_ADDRSTRLEN> buf;
    inet_ntop(AF_INET, &ip, buf.data(), buf.size());
    return string(buf.data());
}

string ipv6_to_string(const uint8_t* ip) {
    array<char, INET6_ADDRSTRLEN> buf;
    inet_ntop(AF_INET6, ip, buf.data(), buf.size());
    return string(buf.data());
}

string mac_to_string(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return string(buf);
}

string get_service_name(uint16_t port) {
    static const map<uint16_t, string> port_map = {
        {20, "FTP-Data"}, {21, "FTP"}, {22, "SSH"}, {23, "Telnet"},
        {25, "SMTP"}, {53, "DNS"}, {67, "DHCP"}, {68, "DHCP"},
        {69, "TFTP"}, {80, "HTTP"}, {110, "POP3"}, {119, "NNTP"},
        {123, "NTP"}, {143, "IMAP"}, {161, "SNMP"}, {194, "IRC"},
        {443, "HTTPS"}, {465, "SMTPS"}, {514, "Syslog"}, {587, "SMTP"},
        {993, "IMAPS"}, {995, "POP3S"}, {1080, "SOCKS"}, {1433, "MSSQL"},
        {1521, "Oracle"}, {3306, "MySQL"}, {3389, "RDP"}, 
        {5432, "PostgreSQL"}, {5900, "VNC"}, {6379, "Redis"},
        {8080, "HTTP-Alt"}, {8443, "HTTPS-Alt"}, {27017, "MongoDB"}
    };
    auto it = port_map.find(port);
    return (it != port_map.end()) ? it->second : "Unknown";
}

string protocol_to_string(uint8_t proto) {
    switch (proto) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 58: return "ICMPv6";
        default: return "OTHER";
    }
}

// ============================================================================
// JSON BUILDER (Different approach - using ostringstream)
// ============================================================================
class JsonBuilder {
    ostringstream oss_;
    bool first_;
    bool is_obj_;

public:
    explicit JsonBuilder(bool is_object = true) : first_(true), is_obj_(is_object) {
        oss_ << (is_object ? '{' : '[');
    }

    JsonBuilder& add_key(const string& key) {
        if (!first_) oss_ << ',';
        first_ = false;
        oss_ << '"' << escape(key) << "\":";
        return *this;
    }

    JsonBuilder& add_string(const string& val) {
        oss_ << '"' << escape(val) << '"';
        return *this;
    }

    JsonBuilder& add_number(uint64_t val) {
        oss_ << val;
        return *this;
    }

    JsonBuilder& add_number(uint32_t val) {
        oss_ << val;
        return *this;
    }

    JsonBuilder& add_number(uint16_t val) {
        oss_ << val;
        return *this;
    }

    JsonBuilder& add_number(double val, int prec = 2) {
        oss_ << fixed << setprecision(prec) << val;
        return *this;
    }

    JsonBuilder& add_bool(bool val) {
        oss_ << (val ? "true" : "false");
        return *this;
    }

    JsonBuilder& start_array(const string& key) {
        if (!first_) oss_ << ',';
        first_ = false;
        oss_ << '"' << escape(key) << "\":[";
        return *this;
    }

    JsonBuilder& start_object() {
        if (!first_) oss_ << ',';
        first_ = false;
        oss_ << '{';
        first_ = true;
        return *this;
    }

    JsonBuilder& end_object() {
        oss_ << '}';
        return *this;
    }

    JsonBuilder& end_array() {
        oss_ << ']';
        return *this;
    }

    string str() const {
        return oss_.str() + (is_obj_ ? "}" : "]");
    }

private:
    string escape(const string& s) {
        string out;
        for (char c : s) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default: out += c;
            }
        }
        return out;
    }
};

// ============================================================================
// PACKET PROCESSOR
// ============================================================================
void process_raw_packet(const struct pcap_pkthdr* hdr, const u_char* data) {
    if (hdr->caplen < sizeof(EthHeader)) {
        return;
    }

    const EthHeader* eth = reinterpret_cast<const EthHeader*>(data);
    uint16_t eth_type = ntohs(eth->eth_type);

    NetPacket pkt;
    pkt.capture_time = current_timestamp();
    pkt.src_port = 0;
    pkt.dst_port = 0;
    pkt.pkt_size = hdr->len;

    const u_char* transport = nullptr;
    uint8_t ip_proto = 0;

    if (eth_type == 0x0800) {  // IPv4
        if (hdr->caplen < sizeof(EthHeader) + sizeof(IPv4Hdr)) return;
        const IPv4Hdr* ip = reinterpret_cast<const IPv4Hdr*>(data + sizeof(EthHeader));
        int ip_hlen = (ip->ver_ihl & 0x0F) * 4;
        if (ip_hlen < 20) return;

        pkt.src_ip = ipv4_to_string(ip->saddr);
        pkt.dst_ip = ipv4_to_string(ip->daddr);
        ip_proto = ip->proto;
        transport = data + sizeof(EthHeader) + ip_hlen;
    }
    else if (eth_type == 0x86DD) {  // IPv6
        if (hdr->caplen < sizeof(EthHeader) + sizeof(IPv6Hdr)) return;
        const IPv6Hdr* ip6 = reinterpret_cast<const IPv6Hdr*>(data + sizeof(EthHeader));
        pkt.src_ip = ipv6_to_string(ip6->saddr);
        pkt.dst_ip = ipv6_to_string(ip6->daddr);
        ip_proto = ip6->next_hdr;
        transport = data + sizeof(EthHeader) + sizeof(IPv6Hdr);
    }
    else {
        return;
    }

    pkt.proto = protocol_to_string(ip_proto);

    size_t transport_offset = transport - data;
    if (transport_offset >= hdr->caplen) return;

    switch (ip_proto) {
        case 6:  // TCP
            if (hdr->caplen >= transport_offset + sizeof(TCPHdr)) {
                const TCPHdr* tcp = reinterpret_cast<const TCPHdr*>(transport);
                pkt.src_port = ntohs(tcp->sport);
                pkt.dst_port = ntohs(tcp->dport);
            }
            break;
        case 17:  // UDP
            if (hdr->caplen >= transport_offset + sizeof(UDPHdr)) {
                const UDPHdr* udp = reinterpret_cast<const UDPHdr*>(transport);
                pkt.src_port = ntohs(udp->sport);
                pkt.dst_port = ntohs(udp->dport);
            }
            break;
    }

    pkt.app_service = get_service_name(pkt.dst_port);
    if (pkt.app_service == "Unknown") {
        pkt.app_service = get_service_name(pkt.src_port);
    }

    g_packet_buffer.push(pkt);
    g_byte_count += pkt.pkt_size;
    g_proto_stats[pkt.proto]++;
    g_service_stats[pkt.app_service]++;
    
}

void packet_callback(u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt) {
    if (!g_is_running) return;
    process_raw_packet(hdr, pkt);
}

// ============================================================================
// CAPTURE THREAD
// ============================================================================
void capture_worker(string dev_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    g_pcap_handle = pcap_open_live(dev_name.c_str(), 65535, 1, 100, errbuf);
    if (!g_pcap_handle) {
        cerr << "Failed to open device: " << errbuf << endl;
        g_is_running = false;
        return;
    }

    // Set filter to capture only IP packets
    struct bpf_program fp;
    bpf_u_int32 netmask = 0xFFFFFF00;
    
    if (pcap_compile(g_pcap_handle, &fp, "ip", 0, netmask) == -1) {
        cerr << "Warning: Couldn't parse filter" << endl;
    } else {
        pcap_setfilter(g_pcap_handle, &fp);
        pcap_freecode(&fp);
    }

    while (g_is_running && !g_should_stop) {
        pcap_dispatch(g_pcap_handle, 100, packet_callback, nullptr);
    }

    pcap_close(g_pcap_handle);
    g_pcap_handle = nullptr;
}

// ============================================================================
// API RESPONSE BUILDERS
// ============================================================================
string build_device_list() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return "[]";
    }

    JsonBuilder builder(false);  // array
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        builder.start_object();
        builder.add_key("name").add_string(d->name ? d->name : "");
        builder.add_key("description").add_string(d->description ? d->description : "");
        builder.end_object();
    }
    pcap_freealldevs(alldevs);
    return builder.str();
}

string build_packets_json(const string& proto_filt, const string& src_filt, const string& dst_filt) {
    vector<NetPacket> packets = g_packet_buffer.get_all();
    JsonBuilder builder(false);

    for (const auto& p : packets) {
        if (!proto_filt.empty() && p.proto != proto_filt) continue;
        if (!src_filt.empty() && p.src_ip.find(src_filt) == string::npos) continue;
        if (!dst_filt.empty() && p.dst_ip.find(dst_filt) == string::npos) continue;

        builder.start_object();
        builder.add_key("time").add_string(p.capture_time);
        builder.add_key("src").add_string(p.src_ip);
        builder.add_key("dst").add_string(p.dst_ip);
        builder.add_key("sport").add_number(p.src_port);
        builder.add_key("dport").add_number(p.dst_port);
        builder.add_key("proto").add_string(p.proto);
        builder.add_key("size").add_number(p.pkt_size);
        builder.add_key("service").add_string(p.app_service);
        builder.end_object();
    }
    return builder.str();
}

string build_stats_json() {
    size_t total = g_packet_buffer.size();
    uint64_t bytes = g_byte_count.load();
    double avg = total > 0 ? static_cast<double>(bytes) / total : 0.0;

    JsonBuilder builder;
    builder.add_key("total_packets").add_number(total);
    builder.add_key("total_bytes").add_number(bytes);
    builder.add_key("avg_size").add_number(avg);
    
    builder.start_array("protocols");
    for (const auto& kv : g_proto_stats) {
        builder.start_object();
        builder.add_key("name").add_string(kv.first);
        builder.add_key("count").add_number(kv.second.load());
        builder.end_object();
    }
    builder.end_array();

    builder.start_array("services");
    int svc_count = 0;
    for (const auto& kv : g_service_stats) {
        if (svc_count++ >= 8) break;
        builder.start_object();
        builder.add_key("name").add_string(kv.first);
        builder.add_key("count").add_number(kv.second.load());
        builder.end_object();
    }
    builder.end_array();

    return builder.str();
}

string build_status_json() {
    JsonBuilder builder;
    builder.add_key("active").add_bool(g_is_running.load());
    builder.add_key("packet_count").add_number(g_packet_buffer.size());
    return builder.str();
}


// ============================================================================
// HTTP SERVER (Different approach - simpler request handling)
// ============================================================================
struct HttpRequest {
    string method;
    string path;
    map<string, string> params;
};

HttpRequest parse_request(const string& req_str) {
    HttpRequest req;
    istringstream iss(req_str);
    iss >> req.method;
    
    string full_path;
    iss >> full_path;
    
    size_t qpos = full_path.find('?');
    if (qpos != string::npos) {
        req.path = full_path.substr(0, qpos);
        string query = full_path.substr(qpos + 1);
        
        size_t start = 0;
        while (start < query.length()) {
            size_t eq = query.find('=', start);
            size_t amp = query.find('&', start);
            if (eq == string::npos) break;
            
            string key = query.substr(start, eq - start);
            string val;
            if (amp == string::npos) {
                val = query.substr(eq + 1);
                start = query.length();
            } else {
                val = query.substr(eq + 1, amp - eq - 1);
                start = amp + 1;
            }
            req.params[key] = val;
        }
    } else {
        req.path = full_path;
    }
    return req;
}

void handle_http_client(SOCKET client_sock) {
    char buffer[4096];
    int received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        closesocket(client_sock);
        return;
    }
    buffer[received] = '\0';
    string request(buffer);

    HttpRequest req = parse_request(request);
    string response_body;
    string content_type = "application/json";
    int status_code = 200;

    // Route handling (different API structure)
    if (req.path == "/" || req.path == "/index.html") {
        ifstream file("web/index.html");
        if (!file) file.open("../web/index.html");
        if (file) {
            response_body = string((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
            content_type = "text/html";
        } else {
            response_body = "<!DOCTYPE html><html><head><title>Network Traffic Analyzer</title></head><body><h1>Network Traffic Analyzer</h1><p>Error: index.html not found. Please ensure web files are in the correct directory.</p></body></html>";
            content_type = "text/html";
        }
    }
    else if (req.path == "/styles.css") {
        ifstream file("web/styles.css");
        if (!file) file.open("../web/styles.css");
        if (file) {
            response_body = string((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
            content_type = "text/css";
        }
    }
    else if (req.path == "/app.js") {
        ifstream file("web/app.js");
        if (!file) file.open("../web/app.js");
        if (file) {
            response_body = string((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
            content_type = "application/javascript";
        }
    }
    else if (req.path == "/api/interfaces") {
        response_body = build_device_list();
    }
    else if (req.path == "/api/begin") {
        string dev = req.params["device"];
        // URL decode the device name (convert %5C to \, etc.)
        string decoded;
        for (size_t i = 0; i < dev.length(); i++) {
            if (dev[i] == '%' && i + 2 < dev.length()) {
                int hex;
                sscanf(dev.substr(i + 1, 2).c_str(), "%2x", &hex);
                decoded += (char)hex;
                i += 2;
            } else if (dev[i] == '+') {
                decoded += ' ';
            } else {
                decoded += dev[i];
            }
        }
        dev = decoded;
        
        if (!dev.empty() && !g_is_running) {
            g_packet_buffer.clear();
            g_proto_stats.clear();
            g_service_stats.clear();
            g_byte_count = 0;
            g_is_running = true;
            g_should_stop = false;
            g_capture_thread = thread(capture_worker, dev);
            
            JsonBuilder jb;
            jb.add_key("success").add_bool(true);
            jb.add_key("interface").add_string(dev);
            response_body = jb.str();
        } else {
            JsonBuilder jb;
            jb.add_key("success").add_bool(false);
            jb.add_key("error").add_string("Already running or no device specified");
            response_body = jb.str();
        }
    }
    else if (req.path == "/api/halt") {
        g_is_running = false;
        g_should_stop = true;
        if (g_capture_thread.joinable()) {
            g_capture_thread.join();
        }
        JsonBuilder jb;
        jb.add_key("success").add_bool(true);
        response_body = jb.str();
    }
    else if (req.path == "/api/flows") {
        string proto = req.params["protocol"];
        string src = req.params["src"];
        string dst = req.params["dst"];
        response_body = build_packets_json(proto, src, dst);
    }
    else if (req.path == "/api/metrics") {
        response_body = build_stats_json();
    }
    else if (req.path == "/api/state") {
        response_body = build_status_json();
    }
    else {
        status_code = 404;
        JsonBuilder jb;
        jb.add_key("error").add_string("Not found");
        response_body = jb.str();
    }

    ostringstream response;
    response << "HTTP/1.1 " << status_code << " OK\r\n";
    response << "Content-Type: " << content_type << "\r\n";
    response << "Access-Control-Allow-Origin: *\r\n";
    response << "Content-Length: " << response_body.length() << "\r\n";
    response << "Connection: close\r\n\r\n";
    response << response_body;

    string resp_str = response.str();
    send(client_sock, resp_str.c_str(), (int)resp_str.length(), 0);
    closesocket(client_sock);
}

// ============================================================================
// MAIN ENTRY
// ============================================================================
int main() {
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        cerr << "WSAStartup failed" << endl;
        return 1;
    }

    SOCKET server = socket(AF_INET, SOCK_STREAM, 0);
    if (server == INVALID_SOCKET) {
        cerr << "Socket creation failed" << endl;
        WSACleanup();
        return 1;
    }

    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8080);

    if (bind(server, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        cerr << "Bind failed. Error: " << WSAGetLastError() << endl;
        cerr << "Try running as Administrator!" << endl;
        closesocket(server);
        WSACleanup();
        return 1;
    }

    if (listen(server, SOMAXCONN) == SOCKET_ERROR) {
        cerr << "Listen failed" << endl;
        closesocket(server);
        WSACleanup();
        return 1;
    }

    cout << "========================================" << endl;
    cout << "  Network Traffic Analyzer" << endl;
    cout << "  URL: http://localhost:8080" << endl;
    cout << "  Run as Administrator for capture!" << endl;
    cout << "  Press Ctrl+C to stop" << endl;
    cout << "========================================" << endl;

    while (true) {
        sockaddr_in client_addr{};
        int client_len = sizeof(client_addr);
        SOCKET client = accept(server, (sockaddr*)&client_addr, &client_len);
        if (client == INVALID_SOCKET) continue;
        thread(handle_http_client, client).detach();
    }

    closesocket(server);
    WSACleanup();
    return 0;
}
