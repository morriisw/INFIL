#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/select.h>
#include <thread>
#include <mutex>
#include <vector>
#include <tins/tins.h>
#include <tins/sniffer.h>
#include <iomanip>
#include <sstream>
#include <tuple>
#include "scanner.hpp"

mutex io_mutex;

// TCP Connect Scan (Full Handshake)
// Check if TCP port is open using non-blocking connect + select()
TCPPortStatus Scanner::isTCPPortOpen(int port) {
    addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC; // Support IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;

    string port_str = to_string(port);
    if (getaddrinfo(target_ip_.c_str(), port_str.c_str(), &hints, &res) != 0)
        return TCP_FILTERED;

    TCPPortStatus status = TCP_FILTERED;

    for (addrinfo *p = res; p != nullptr; p = p->ai_next) {
        int sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0) continue;

        // Set socket to non-blocking
        fcntl(sockfd, F_SETFL, O_NONBLOCK);
        connect(sockfd, p->ai_addr, p->ai_addrlen); // Non-blocking connect

        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sockfd, &fdset);

        timeval tv{};
        tv.tv_sec = 1;  // 1 second timeout
        tv.tv_usec = 0;

        if (select(sockfd + 1, nullptr, &fdset, nullptr, &tv) > 0) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);

            if (so_error == 0) {
                status = TCP_OPEN; // OPEN
                close(sockfd);
                break;
            } else if (so_error == ECONNREFUSED) {
                status = TCP_CLOSED; // CLOSED
            } else {
                status = TCP_FILTERED; // FILTERED or unreachable
            }
        }
        close(sockfd);
    }

    freeaddrinfo(res);
    return status;
}

// UDP Scan
UDPScanResult Scanner::isUDPPortOpen(int port) {
    addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    std::string port_str = std::to_string(port);
    std::vector<uint8_t> response;
    UDPPortStatus status = UDP_OPEN_FILTERED;

    if (getaddrinfo(target_ip_.c_str(), port_str.c_str(), &hints, &res) != 0)
        return { UDP_OPEN_FILTERED, response };

    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        int sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0) continue;

        timeval tv{};
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        // Craft protocol-specific payload
        std::vector<uint8_t> payload;

        if (port == 53) {
            // DNS standard query (google.com A record)
            payload = {
                0x12, 0x34,             // Transaction ID
                0x01, 0x00,             // Standard query
                0x00, 0x01,             // Questions: 1
                0x00, 0x00,             // Answer RRs
                0x00, 0x00,             // Authority RRs
                0x00, 0x00,             // Additional RRs
                0x06, 'g','o','o','g','l','e',
                0x03, 'c','o','m',
                0x00,                   // End of host
                0x00, 0x01,             // Type A
                0x00, 0x01              // Class IN
            };
        } else if (port == 123) {
            // Basic NTP request (mode 3: client)
            payload.resize(48, 0);
            payload[0] = 0x1B; // LI=0, VN=3, Mode=3
        } else if (port == 161) {
            // SNMP GET request for sysDescr.0
            payload = {
                0x30, 0x26,                   // Sequence
                0x02, 0x01, 0x00,             // SNMP version 1
                0x04, 0x06, 'p','u','b','l','i','c', // community
                0xA0, 0x19,                   // GET request
                0x02, 0x04, 0x70, 0x01, 0x00, 0x01, // request-id
                0x02, 0x01, 0x00,             // error-status
                0x02, 0x01, 0x00,             // error-index
                0x30, 0x0B,                   // varbind list
                0x30, 0x09,
                0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // sysDescr
                0x05, 0x00                    // NULL value
            };
        } else {
            const char* msg = "Hello";
            payload = std::vector<uint8_t>(msg, msg + strlen(msg));
        }

        // Try sending and receiving up to 2 times (default nmap behaviour)
        for (int attempt = 0; attempt < 2 && status == UDP_OPEN_FILTERED; ++attempt) {
            sendto(sockfd, payload.data(), payload.size(), 0, p->ai_addr, p->ai_addrlen);

            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(sockfd, &readfds);

            int rv = select(sockfd + 1, &readfds, nullptr, nullptr, &tv);
            if (rv > 0) {
                sockaddr_storage from{};
                socklen_t fromlen = sizeof(from);
                char buffer[1024];
                int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (sockaddr*)&from, &fromlen);

                if (n >= 0) {
                    response.assign(buffer, buffer + n);
                    status = UDP_OPEN;
                    break;
                } else {
                    if (errno == ECONNREFUSED) {
                        status = UDP_CLOSED;
                        break;
                    }
                }
            } else if (rv < 0) {
                break; // select() error
            }
        }

        close(sockfd);
        if (status != UDP_OPEN_FILTERED)
            break;
    }

    freeaddrinfo(res);
    return { status, response };
}

string Scanner::identifyService(const string& banner, int port) {
    if (banner.find("SSH-") == 0) return "ssh";
    if (banner.find("HTTP/") == 0 || banner.find("Server:") != string::npos) return "http";
    if (banner.find("FTP") != string::npos) return "ftp";
    if (banner.find("SMTP") != string::npos || banner.find("ESMTP") != string::npos) return "smtp";
    if (banner.find("POP3") != string::npos) return "pop3";
    if (banner.find("IMAP") != string::npos) return "imap";
    if (banner.find("Telnet") != string::npos) return "telnet";
    if (banner.find("VNC") != string::npos) return "vnc";
    if (banner.find("MySQL") != string::npos) return "mysql";
    if (banner.find("MongoDB") != string::npos) return "mongodb";
    
    // --- TLS/SSL detection ---
    if (banner.size() >= 3) {
        uint8_t byte0 = static_cast<uint8_t>(banner[0]);
        uint8_t byte1 = static_cast<uint8_t>(banner[1]);
        uint8_t byte2 = static_cast<uint8_t>(banner[2]);

        if (byte0 == 0x16 && byte1 == 0x03 && byte2 <= 0x04) {
            return "https";
        }
    }

    // Port-based fallback if nothing matched
    switch (port) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "domain";
        case 80: return "http";
        case 110: return "pop3";
        case 143: return "imap";
        case 443: return "https";
        case 3306: return "mysql";
        case 6379: return "redis";
        default: break;
    }

    return "Unknown";
}

// Attempt to grab a banner from an open TCP service
string Scanner::grabBanner(int port) {
    addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC;             // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;         // TCP

    string port_str = to_string(port);
    if (getaddrinfo(target_ip_.c_str(), port_str.c_str(), &hints, &res) != 0)
        return "";

    string banner = "";

    for (addrinfo* p = res; p != nullptr && banner.empty(); p = p->ai_next) {
        int sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0) continue;

        timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) < 0) {
            close(sockfd);
            continue;
        }

        // Send newline or dummy data to provoke a response
        const char* probe = "\n";
        send(sockfd, probe, strlen(probe), 0);

        char buffer[1024];
        int n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            banner = string(buffer);
        }
        close(sockfd);
    }

    freeaddrinfo(res);
    return identifyService(banner, port);
}

void Scanner::scanTCPPorts(int start, int end, bool verbose) {
    std::cout << "\n[*] Starting TCP Scan on " << target_ip_ << "\n";

    vector<thread> threads;
    const int MAX_THREADS = 500;
    vector<pair<int, string>> results;
    mutex result_mutex;

    for (int port = start; port <= end; ++port) {
        threads.emplace_back([this, port, &results, &result_mutex]() {
            int status = isTCPPortOpen(port);
            string result;

            if (status == TCP_OPEN) {
                string banner = grabBanner(port);
                result = to_string(port) + "/tcp open";
                if (banner != "Unknown")
                    result += " " + banner;
            } else if (status == TCP_CLOSED) {
                result = to_string(port) + "/tcp closed";
            } else {
                string banner = grabBanner(port);
                result = to_string(port) + "/tcp filtered";
                if (banner != "Unknown")
                    result += " " + banner;
            }

            lock_guard<mutex> lock(result_mutex);
            results.emplace_back(port, result);
        });

        if (threads.size() >= MAX_THREADS) {
            for (auto& t : threads) t.join();
            threads.clear();
        }
    }

    for (auto& t : threads) t.join();
    sort(results.begin(), results.end());

    // Parse and store structured rows, and determine column widths
    vector<tuple<string, string, string>> parsed_rows;
    size_t port_col_width = 0;
    size_t state_col_width = 0;
    size_t service_col_width = 0;

    for (const auto& [_, msg] : results) {
        istringstream iss(msg);
        string port_proto, state, service;

        iss >> port_proto >> state;
        getline(iss, service);
        if (!service.empty() && service[0] == ' ')
            service = service.substr(1); // trim leading space

        parsed_rows.emplace_back(port_proto, state, service);

        port_col_width = max(port_col_width, port_proto.length());
        state_col_width = max(state_col_width, state.length());
        service_col_width = max(service_col_width, service.length());
    }

    cout << "\n";

    // Print header
    cout << left
         << setw(port_col_width + 2) << "PORT"
         << setw(state_col_width + 2) << "STATE"
         << setw(service_col_width + 2) << "SERVICE"
         << "\n";

    // Print data
    for (const auto& [port_proto, state, service] : parsed_rows) {
        if (verbose != true && state == "closed") {
            continue;
        }
        cout << left
             << setw(port_col_width + 2) << port_proto
             << setw(state_col_width + 2) << state
             << setw(service_col_width + 2) << service
             << "\n";
    }

    cout << "\n";
}

string Scanner::identifyUDPService(int port, const vector<uint8_t>& response) {
    if (port == 53 && response.size() >= 4 && response[2] == 0x81 && response[3] == 0x80)
        return "domain";
    if (port == 123 && response.size() >= 48 && (response[0] & 0x07) >= 4)
        return "ntp";
    if (port == 161 && response.size() > 10) {
        string resp_str(response.begin(), response.end());
        if (response[0] == 0x30 && resp_str.find("public") != string::npos)
            return "snmp";
    }
    if (port == 1900) {
        string s(response.begin(), response.end());
        if (s.find("HTTP/1.1 200 OK") != string::npos && s.find("ST:") != string::npos)
            return "ssdp/upnp";
    }
    if (port == 137 && response.size() > 2 && (response[2] & 0x80)) {
        return "netbios";
    }

    return "Unknown";
}

void Scanner::scanUDPPorts(int start, int end, bool verbose) {
    std::cout << "\n[*] Starting UDP Scan on " << target_ip_ << "\n";

    vector<thread> threads;
    const int MAX_THREADS = 500;
    vector<pair<int, string>> results;
    mutex result_mutex;

    for (int port = start; port <= end; ++port) {
        threads.emplace_back([this, port, &results, &result_mutex]() {
            UDPScanResult resultObj = isUDPPortOpen(port);
            string result;

            if (resultObj.status == UDP_OPEN) {
                string service = identifyUDPService(port, resultObj.response);
                result = to_string(port) + "/udp open";
                if (service != "Unknown")
                    result += " " + service;
            } else if (resultObj.status == UDP_CLOSED) {
                result = to_string(port) + "/udp closed";
            } else {
                // cannot reliably use default service detection for UDP scans
                result = to_string(port) + "/udp open|filtered"; 
            }

            lock_guard<mutex> lock(result_mutex);
            results.emplace_back(port, result);
        });

        if (threads.size() >= MAX_THREADS) {
            for (auto& t : threads) t.join();
            threads.clear();
        }
    }

    for (auto& t : threads) t.join();
    sort(results.begin(), results.end());

    // Parse and store structured rows, and determine column widths
    vector<tuple<string, string, string>> parsed_rows;
    size_t port_col_width = 0;
    size_t state_col_width = 0;
    size_t service_col_width = 0;

    for (const auto& [_, msg] : results) {
        istringstream iss(msg);
        string port_proto, state, service;

        iss >> port_proto >> state;
        getline(iss, service);
        if (!service.empty() && service[0] == ' ')
            service = service.substr(1); // trim leading space

        parsed_rows.emplace_back(port_proto, state, service);

        port_col_width = max(port_col_width, port_proto.length());
        state_col_width = max(state_col_width, state.length());
        service_col_width = max(service_col_width, service.length());
    }

    cout << "\n";

    // Print header
    cout << left
         << setw(port_col_width + 2) << "PORT"
         << setw(state_col_width + 2) << "STATE"
         << setw(service_col_width + 2) << "SERVICE"
         << "\n";

    // Print data
    for (const auto& [port_proto, state, service] : parsed_rows) {
        if (verbose != true && (state == "closed" || service == "")) {
            continue;
        }
        cout << left
             << setw(port_col_width + 2) << port_proto
             << setw(state_col_width + 2) << state
             << setw(service_col_width + 2) << service
             << "\n";
    }

    cout << "\n";
}

void Scanner::scanSYNPorts(int start_port, int end_port, bool verbose) {
    std::cout << "\n[*] Starting SYN Scan on " << target_ip_ << "\n";

    Tins::NetworkInterface iface = Tins::NetworkInterface::default_interface();
    Tins::IPv4Address src_ip = iface.addresses().ip_addr;

    Tins::PacketSender sender;
    std::mutex result_mutex;

    // Store results to sort later
    std::map<int, string> port_states;
    std::map<int, string> port_banners;

    // Sniffer config
    Tins::SnifferConfiguration config;
    config.set_promisc_mode(false);
    config.set_timeout(3); // Timeout to avoid hanging
    config.set_filter("tcp");

    Tins::Sniffer sniffer(iface.name(), config);
    auto start_time = std::chrono::steady_clock::now();

    // Start sniffing in a separate thread
    std::thread sniff_thread([&]() {
        sniffer.sniff_loop([&](const Tins::PDU& pdu) {
            try {
                const Tins::IP& ip = pdu.rfind_pdu<Tins::IP>();
                const Tins::TCP& tcp = pdu.rfind_pdu<Tins::TCP>();

                int port = tcp.sport();  // Fix: use source port from target
                std::string state;

                if (tcp.get_flag(Tins::TCP::SYN) && tcp.get_flag(Tins::TCP::ACK)) {
                    state = "open";

                    // Send RST to close half-open connection
                    Tins::TCP rst = Tins::TCP(tcp.sport(), tcp.dport());
                    rst.set_flag(Tins::TCP::RST, 1);
                    Tins::IP ip_rst = Tins::IP(ip.src_addr(), ip.dst_addr()) / rst;
                    sender.send(ip_rst);

                    // Grab banner using a full TCP connection after SYN-ACK
                    string banner = grabBanner(port);
                    std::lock_guard<std::mutex> lock(result_mutex);
                    port_states[port] = state;
                    port_banners[port] = banner;
                } else if (tcp.get_flag(Tins::TCP::RST)) {
                    state = "closed";
                    std::lock_guard<std::mutex> lock(result_mutex);
                    port_states[port] = state;
                }
            } catch (...) {
                return true; // Continue sniffing on failure
            }

            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count() > 5)
                return false; // Stop sniffing after timeout

            return true;
        });
    });

    // Send SYN packets
    for (int port = start_port; port <= end_port; ++port) {
        Tins::TCP tcp = Tins::TCP(port, Tins::TCP::Flags::SYN);
        tcp.set_flag(Tins::TCP::SYN, 1);
        Tins::IP ip = Tins::IP(target_ip_, src_ip) / tcp;

        // Send at IP layer (no Ethernet MAC issues)
        sender.send(ip);
    }

    // Wait for sniffing to complete
    sniff_thread.join();

    // Build parsed rows and track max column widths
    vector<tuple<string, string, string>> parsed_rows;
    size_t port_col_width = 4;    // "PORT"
    size_t state_col_width = 5;   // "STATE"
    size_t service_col_width = 7; // "SERVICE"

    for (int port = start_port; port <= end_port; ++port) {
        string port_proto = to_string(port) + "/tcp";
        string state, service;

        {
            std::lock_guard<std::mutex> lock(result_mutex);
            if (port_states.count(port)) {
                state = port_states[port];
                service = (port_banners.count(port) && port_banners[port] != "Unknown") ? port_banners[port] : "";
            } else {
                state = "filtered";

                string banner = grabBanner(port);
                if (banner != "Unknown") {
                    service = banner;
                    port_banners[port] = banner;
                } else {
                    service = "";
                }
            }
        }

        parsed_rows.emplace_back(port_proto, state, service);

        port_col_width = std::max(port_col_width, port_proto.length());
        state_col_width = std::max(state_col_width, state.length());
        service_col_width = std::max(service_col_width, service.length());
    }

    cout << "\n";

    // Print header
    std::cout << std::left
            << std::setw(port_col_width + 2) << "PORT"
            << std::setw(state_col_width + 2) << "STATE"
            << std::setw(service_col_width + 2) << "SERVICE"
            << "\n";

    // Print data rows
    for (const auto& [port_proto, state, service] : parsed_rows) {
        if (verbose != true && state == "closed") {
            continue;
        }
        std::cout << std::left
                << std::setw(port_col_width + 2) << port_proto
                << std::setw(state_col_width + 2) << state
                << std::setw(service_col_width + 2) << service
                << "\n";
    }

    cout << "\n";
}