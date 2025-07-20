#ifndef SCANNER_HPP
#define SCANNER_HPP

#include <string>
#include <vector>

using namespace std;

enum UDPPortStatus {
    UDP_OPEN,
    UDP_CLOSED,
    UDP_OPEN_FILTERED
};

enum TCPPortStatus {
    TCP_OPEN,
    TCP_CLOSED,
    TCP_FILTERED
};

struct UDPScanResult {
    UDPPortStatus status;
    vector<uint8_t> response;
};

class Scanner {
    public:
        Scanner(const string& target) {
            target_ip_ = target;
        }

        void scanTCPPorts(int start_port, int end_port, bool verbose);
        void scanUDPPorts(int start_port, int end_port, bool verbose);
        void scanSYNPorts(int start_port, int end_port, bool verbose);

    private:
        string target_ip_;  // Target IP address

        TCPPortStatus isTCPPortOpen(int port);
        UDPScanResult isUDPPortOpen(int port);

        string grabBanner(int port);
        string identifyService(const string& banner, int port);
        string identifyUDPService(int port, const vector<uint8_t>& response);
};

#endif

