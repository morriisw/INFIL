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

/// @brief Checks if a port is open using TCP Connect Scan
/// @param port is the port number to scan
/// @return A TCP port status (open/closed/filtered)
TCPPortStatus Scanner::isTCPPortOpen(int port) {
    addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC;      // Support IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;  // TCP socket

    string port_str = to_string(port);
    if (getaddrinfo(target_ip_.c_str(), port_str.c_str(), &hints, &res) != 0)
        return TCP_FILTERED;  // Filtered if nonzero error code

    TCPPortStatus status = TCP_FILTERED;

    for (addrinfo *p = res; p != nullptr; p = p->ai_next) {
        int sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0) continue;

        // Set socket to non-blocking mode to prevent blocking of connect()
        fcntl(sockfd, F_SETFL, O_NONBLOCK);

        // Initiate non-blocking connect and return immediately
        connect(sockfd, p->ai_addr, p->ai_addrlen);

        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sockfd, &fdset);

        timeval tv{};
        tv.tv_sec = 1;  // Wait 1 second for connection
        tv.tv_usec = 0;

        // Wait for socket to be writable or timeout
        if (select(sockfd + 1, nullptr, &fdset, nullptr, &tv) > 0) {
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);

            if (so_error == 0) {
                // Connection succeeded (port open)
                status = TCP_OPEN;
                close(sockfd);
                break;
            } else if (so_error == ECONNREFUSED) {
                // Connection refused (port closed)
                status = TCP_CLOSED;
            } else {
                // Port filtered
                status = TCP_FILTERED;
            }
        }
        close(sockfd);
    }

    freeaddrinfo(res);
    return status;
}

/// @brief Checks if a port is open using UDP Scan
/// @param port is the port number to scan
/// @return A UDP port status (open/closed/open|filtered) and a raw payload returned from 
///         scan stored within a struct
UDPScanResult Scanner::isUDPPortOpen(int port) {
    addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    std::string port_str = std::to_string(port);
    std::vector<uint8_t> response;
    UDPPortStatus status = UDP_OPEN_FILTERED;

    if (getaddrinfo(target_ip_.c_str(), port_str.c_str(), &hints, &res) != 0)
        return { UDP_OPEN_FILTERED, response };  // Filtered if nonzero error code

    // Some hostnames or IPs can be resolved to more than one addrinfo structure
    // i.e. both IPv4 and IPv6 addresses
    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        int sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0) continue;

        timeval tv{};
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        // Craft protocol-specific payload for common UDP services
        std::vector<uint8_t> payload;

        if (port == 53) {
            // DNS standard query (google.com A record)
            payload = {
                0x12, 0x34,                     // Transaction ID
                0x01, 0x00,                     // Standard query
                0x00, 0x01,                     // Questions: 1
                0x00, 0x00,                     // Answer RRs
                0x00, 0x00,                     // Authority RRs
                0x00, 0x00,                     // Additional RRs
                0x06, 'g','o','o','g','l','e',  // QNAME: google
                0x03, 'c','o','m',              // QNAME: com
                0x00,                           // End of QNAME
                0x00, 0x01,                     // Type A
                0x00, 0x01                      // Class IN
            };
        } else if (port == 69) {
            // TFTP read request for "test"
            payload = {
                0x00, 0x01,                // Opcode: 1 = Read Request (RRQ)
                't','e','s','t', 0x00,     // Filename: "test"
                'o','c','t','e','t', 0x00  // Mode: "octet" (raw binary)
            };
        } else if (port == 123) {
            // Basic NTP client request
            payload.resize(48, 0);
            payload[0] = 0x1B;  // LI (Leap Indicator) = 0, VN (Version Number) = 3, Mode = 3 (Client Mode)
        } else if (port == 137) {
            // NetBIOS name service query
            payload = {
                0x81, 0x00, 0x00, 0x10,           // Transaction ID + Flags
                0x00, 0x01, 0x00, 0x00,           // Questions = 1
                0x00, 0x00, 0x00, 0x00,           // No answers/authority/additional
                0x20,                             // Name length (32 bytes)
                'C','K','A','A','A','A','A','A',
                'A','A','A','A','A','A','A','A',
                'A','A','A','A','A','A','A','A',
                'A','A','A','A','A','A','A','A',  // Encoded NetBIOS name
                0x00, 0x00, 0x21, 0x00, 0x01      // 1 byte suffix (Workstation Service), Type NB (NetBIOS name), Class IN (Internet)
            };
        } else if (port == 161) {
            // SNMP GET request for sysDescr.0
            payload = {
                0x30, 0x26,                                // Sequence
                0x02, 0x01, 0x00,                          // SNMP version 1
                0x04, 0x06, 'p','u','b','l','i','c',       // Community string: public
                0xA0, 0x19,                                // GETRequest PDU
                0x02, 0x04, 0x70, 0x01, 0x00, 0x01,        // Request-id
                0x02, 0x01, 0x00,                          // Error status
                0x02, 0x01, 0x00,                          // Error index
                0x30, 0x0B,                                // Variable bindings list
                0x30, 0x09,                                // VarBind
                0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,  // sysDescr.0 OID
                0x05, 0x00                                 // NULL value
            };
        } else if (port == 500) {
            // ISAKMP (IKE Phase 1) header
            payload = {
                0x00, 0x00, 0x00, 0x00,  // Initiator cookie
                0x00, 0x00, 0x00, 0x00,  // Responder cookie
                0x01,                    // Next payload: SA (Security Association)
                0x10,                    // Version
                0x02,                    // Exchange type: Identity Protection (IKEv1)
                0x00,                    // Flags
                0x00, 0x00, 0x00, 0x00,  // Message ID
                0x00, 0x00, 0x00, 0x1C   // Length
            };
        } else if (port == 514) {
            // Syslog test message
            const char* msg = "<13>Test syslog message\n";  // <13> = facility: user-level (1), severity: notice (5)
            payload = std::vector<uint8_t>(msg, msg + strlen(msg));
        } else if (port == 520) {
            // RIP request
            payload = {
                0x01,       // Command: Request
                0x02,       // Version: 2
                0x00, 0x00  // Unused
            };
        } else if (port == 1900) {
            // SSDP M-SEARCH discovery request
            const char* msg =
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"  // UDP multicast (only works when target is on local network)
                "MAN: \"ssdp:discover\"\r\n"
                "MX: 1\r\n"                       // Max wait time before responding   
                "ST: ssdp:all\r\n"                // Query for all services
                "\r\n";
            payload = std::vector<uint8_t>(msg, msg + strlen(msg));
        } else {
            // Default UDP payload "Hello"
            const char* msg = "Hello";
            payload = std::vector<uint8_t>(msg, msg + strlen(msg));
        }

        // Try sending and receiving up to 2 times (default Nmap behaviour)
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
                    // Response received (port open)
                    response.assign(buffer, buffer + n);
                    status = UDP_OPEN;
                    break;
                } else {
                    // Check for ICMP unreachable errors
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

        // Break if status changes from open|filtered to open or closed
        // so other addresses do not need to be tested
        if (status != UDP_OPEN_FILTERED)
            break;
    }

    freeaddrinfo(res);
    return { status, response };
}

/// @brief Identifies the hosted service given a banner string and port number
/// @param banner is the banner returned from the TCP scan
/// @param port is the port number from which to grab the service banner
/// @return The service currently being hosted on the specified port as a string
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
    
    // TLS handshake detection
    if (banner.size() >= 3) {
        uint8_t byte0 = static_cast<uint8_t>(banner[0]);
        uint8_t byte1 = static_cast<uint8_t>(banner[1]);
        uint8_t byte2 = static_cast<uint8_t>(banner[2]);

        if (byte0 == 0x16 && byte1 == 0x03 && byte2 <= 0x04) {
            return "https";
        }
    }

    // Port-based fallback
    switch (port) {
        case 20: return "ftp-data";      // FTP (File Transfer Protocol) data transfer
        case 21: return "ftp";           // FTP (File Transfer Protocol) command/control
        case 22: return "ssh";           // SSH (Secure Shell)
        case 23: return "telnet";        // Telnet
        case 25: return "smtp";          // SMTP (Simple Mail Transfer Protocol)
        case 53: return "domain";        // DNS (Domain Name System)
        case 80: return "http";          // HTTP (Hypertext Transfer Protocol)
        case 110: return "pop3";         // POP3 (Post Office Protocol version 3)
        case 123: return "ntp";          // NTP (Network Time Protocol)
        case 143: return "imap";         // IMAP (Internet Message Access Protocol)
        case 161: return "snmp";         // SNMP (Simple Network Management Protocol)
        case 443: return "https";        // HTTPS (TLS over TCP)
        case 445: return "smb";          // Windows SMB (Server Message Block)
        case 3306: return "mysql";       // MySQL
        case 3389: return "rdp";         // RDP (Remote Desktop Protocol)
        case 5060: return "sip";         // SIP (Session Initiation Protocol)
        case 5432: return "postgresql";  // PostgreSQL
        case 5900: return "vnc";         // VNC (Virtual Network Computing)
        case 6379: return "redis";       // Redis key-value store
        case 8080: return "http-alt";    // Alternate HTTP
        default: break;
    }

    return "Unknown";
}

/// @brief Attempts to grab a banner from an open TCP service
/// @param port is the port number from which to grab the service banner
/// @return The service currently being hosted on the specified port as a string
string Scanner::grabBanner(int port) {
    addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC;      // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;  // TCP

    string port_str = to_string(port);
    if (getaddrinfo(target_ip_.c_str(), port_str.c_str(), &hints, &res) != 0)
        return "";

    string banner = "";

    for (addrinfo* p = res; p != nullptr && banner.empty(); p = p->ai_next) {
        int sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0) continue;

        // 2 second receive timeout to avoid hanging
        timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) < 0) {
            close(sockfd);
            continue;
        }

        // Send newline to provoke response from target
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

/// @brief TCP Connect Scan
/// @param start is the first port number to scan in the port range
/// @param end is the last port number to scan in the port range
/// @param verbose is true or false depending on whether the user wants verbose output
void Scanner::scanTCPPorts(int start, int end, bool verbose) {
    std::cout << "\n[*] Starting TCP Scan on " << target_ip_ << "\n";

    vector<thread> threads;
    const int MAX_THREADS = 500; // Maximum limit of 500 threads
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

        // Limit max concurrent threads
        if (threads.size() >= MAX_THREADS) {
            for (auto& t : threads) t.join();
            threads.clear();
        }
    }

    for (auto& t : threads) t.join();      // Join remaining threads
    sort(results.begin(), results.end());  // Sort results by port

    // Parse results and determine max column widths for formatting
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
            service = service.substr(1); // Trim leading space

        parsed_rows.emplace_back(port_proto, state, service);

        port_col_width = max(port_col_width, port_proto.length());
        state_col_width = max(state_col_width, state.length());
        service_col_width = max(service_col_width, service.length());
    }

    cout << "\n";

    // Print header row
    cout << left
         << setw(port_col_width + 2) << "PORT"
         << setw(state_col_width + 2) << "STATE"
         << setw(service_col_width + 2) << "SERVICE"
         << "\n";

    // Print each row, optionally filtering closed ports if verbose == false
    for (const auto& [port_proto, state, service] : parsed_rows) {
        if (!verbose && state == "closed") {
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

/// @brief Identifies UDP service from port number and response data
/// @param port is the port number to scan
/// @param response is the raw response payload from the UDP scan
/// @return The service currently being hosted on the specified port as a string
string Scanner::identifyUDPService(int port, const vector<uint8_t>& response) {

    // DNS (Domain Name System)
    if (port == 53 && response.size() >= 4 && response[2] == 0x81 && response[3] == 0x80)
        return "domain";

    // DHCP (Dynamic Host Configuration Protocol)
    if (port == 67 || port == 68)
        return "dhcp";

    // TFTP (Trivial File Transfer Protocol)
    if (port == 69 && !response.empty())
        return "tftp";

    // NTP (Network Time Protocol)
    if (port == 123 && response.size() >= 48 && (response[0] & 0x07) >= 4)
        return "ntp";

    // NetBIOS Name Service
    if (port == 137 && response.size() > 2 && (response[2] & 0x80)) {
        return "netbios";
    }

    // NetBIOS Datagram Service
    if (port == 138 && !response.empty())
        return "netbios-dgm";

    // SNMP (Simple Network Management Protocol)
    if (port == 161 && response.size() > 10) {
        string resp_str(response.begin(), response.end());
        if (response[0] == 0x30 && resp_str.find("public") != string::npos)
            return "snmp";
    }

    // Syslog
    if (port == 514 && !response.empty())
        return "syslog";

    // RIP (Routing Information Protocol)
    if (port == 520 && !response.empty())
        return "rip";

    // IPP (Internet Printing Protocol)
    if (port == 631 && !response.empty())
        return "ipp";

    // SSDP (Simple Service Discovery Protocol) / UPnP (Universal Plug and Play)
    if (port == 1900) {
        string s(response.begin(), response.end());
        if (s.find("HTTP/1.1 200 OK") != string::npos && s.find("ST:") != string::npos)
            return "ssdp/upnp";
    }

    // SIP (Session Initiation Protocol)
    if (port == 5060 && !response.empty()) {
        string s(response.begin(), response.end());
        if (s.find("SIP") != string::npos)
            return "sip";
    }

    return "Unknown";
}

/// @brief UDP Scan
/// @param start is the first port number to scan in the port range
/// @param end is the last port number to scan in the port range
/// @param verbose is true or false depending on whether the user wants verbose output
void Scanner::scanUDPPorts(int start, int end, bool verbose) {
    std::cout << "\n[*] Starting UDP Scan on " << target_ip_ << "\n";

    vector<thread> threads;
    const int MAX_THREADS = 500;  // Maximum limit of 500 threads
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

        // Limit max concurrent threads
        if (threads.size() >= MAX_THREADS) {
            for (auto& t : threads) t.join();
            threads.clear();
        }
    }

    for (auto& t : threads) t.join();      // Join remaining threads
    sort(results.begin(), results.end());  // Sort results by port

    // Parse results and determine max column widths for formatting
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
            service = service.substr(1); // Trim leading space

        parsed_rows.emplace_back(port_proto, state, service);

        port_col_width = max(port_col_width, port_proto.length());
        state_col_width = max(state_col_width, state.length());
        service_col_width = max(service_col_width, service.length());
    }

    cout << "\n";

    // Print header row
    cout << left
         << setw(port_col_width + 2) << "PORT"
         << setw(state_col_width + 2) << "STATE"
         << setw(service_col_width + 2) << "SERVICE"
         << "\n";

    // Print each row, optionally filtering closed ports if verbose == false
    for (const auto& [port_proto, state, service] : parsed_rows) {
        if (!verbose && (state == "closed" || service == "")) {
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

/// @brief SYN Scan
/// @param start is the first port number to scan in the port range
/// @param end is the last port number to scan in the port range
/// @param verbose is true or false depending on whether the user wants verbose output
void Scanner::scanSYNPorts(int start, int end, bool verbose) {
    std::cout << "\n[*] Starting SYN Scan on " << target_ip_ << "\n";

    Tins::NetworkInterface iface = Tins::NetworkInterface::default_interface();
    Tins::IPv4Address src_ip = iface.addresses().ip_addr;

    Tins::PacketSender sender;
    std::mutex result_mutex;  // Mutex for thread-safety

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

    // Start sniffing on local interface in a separate thread for incoming TCP packets
    std::thread sniff_thread([&]() {
        sniffer.sniff_loop([&](const Tins::PDU& pdu) {
            try {
                const Tins::IP& ip = pdu.rfind_pdu<Tins::IP>();
                const Tins::TCP& tcp = pdu.rfind_pdu<Tins::TCP>();

                int port = tcp.sport();  // Use source port from target response
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

    // Main thread sends SYN packets to different ports on target IP while sniffer thread listens
    for (int port = start; port <= end; ++port) {
        Tins::TCP tcp = Tins::TCP(port, Tins::TCP::Flags::SYN);
        tcp.set_flag(Tins::TCP::SYN, 1);
        Tins::IP ip = Tins::IP(target_ip_, src_ip) / tcp;  // Stack protocol layers and construct raw IP packet

        // Send at IP layer
        sender.send(ip);
    }

    // Wait for sniffing to complete
    sniff_thread.join();

    // Build parsed rows and track max column widths
    vector<tuple<string, string, string>> parsed_rows;
    size_t port_col_width = 4;    // "PORT"
    size_t state_col_width = 5;   // "STATE"
    size_t service_col_width = 7; // "SERVICE"

    for (int port = start; port <= end; ++port) {
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

    // Print header row
    std::cout << std::left
            << std::setw(port_col_width + 2) << "PORT"
            << std::setw(state_col_width + 2) << "STATE"
            << std::setw(service_col_width + 2) << "SERVICE"
            << "\n";

    // Print each row, optionally filtering closed ports if verbose == false
    for (const auto& [port_proto, state, service] : parsed_rows) {
        if (!verbose && state == "closed") {
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