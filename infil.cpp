#include "scanner.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

using namespace std;

string invalidToolString(void) {
    return "Please choose from the following tools:\n"
           "-> Scanner\n"
           "-> Payload\n"
           "-> Listener\n";
}

string correctUsageString(string tool) {
    if (tool == "scanner") {
        return "Usage: ./infil scanner <ip> <port> <type> [-v]";
    } else if (tool == "payload") {
        return "Usage: ./infil payload <lhost> <lport> <type>";
    } else if (tool == "listener") {
        return "Usage: ./infil listener <lport> <protocol>";
    } else {
        return invalidToolString();
    }
}

vector<string> splitString(const string& s, char delimiter) {
    vector<string> tokens;
    string token;
    istringstream tokenStream(s);
    while (getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

string portUsage(void) {
    return "Port Options:\n"
           "-p-              Scan all ports (i.e. 1 to 65535)\n"
           "-p<portnum>      Scan a specific port (e.g. 80)\n"
           "-p<start>-<end>  Scan a range of ports (e.g. 1 to 80)\n";
}

int main(int argc, char* argv[]) {
    // No tool specified
    if (argc == 1) {
        cout << invalidToolString();
        return 1;
    }

    // Extract specified tool
    string tool = std::string(argv[1]);

    // Check for invalid tool
    if (tool != "scanner" && tool != "payload" && tool != "listener") {
        cout << invalidToolString();
        return 1;
    }

    // Check parameters
    if ((tool == "scanner" && (argc < 5 || argc > 6)) || 
        (tool == "payload" && (argc != 5)) || 
        (tool == "listener" && (argc != 4))) {
        cout << correctUsageString(tool);
        return 1;
    }

    // Initialise scanner
    if (tool == "scanner") {
        string ip = argv[2];
        string portInput = argv[3];
        string scanType = argv[4];

        Scanner scanner(ip);
        int portStart;
        int portEnd;
        bool verbose;

        // Verbose mode (include closed ports)
        verbose = (argc == 6 && std::string(argv[5]) == "-v") ? true : false;

        // Determine port/s to be scanned
        if (portInput.length() < 3 || portInput.length() > 13 || portInput.substr(0, 2) != "-p") {
            cout << portUsage();
            return 1;
        } else {
            char delimiter = '-';
            vector<string> ports = splitString(portInput.substr(2, -1), delimiter);
            if (ports.size() == 1) {
                // Single port or no port number
                if (ports.at(0) != "") {
                    // Specific port number
                    portStart = stoi(ports.at(0));
                    portEnd = stoi(ports.at(0));
                } else {
                    // Equivalent nmap -p- functionality
                    portStart = 1;
                    portEnd = 65535;
                }
            } else if (ports.size() == 2) {
                // Port range
                portStart = stoi(ports.at(0));
                portEnd = stoi(ports.at(1));
            }
        }

        // Scan type
        if (scanType == "-T") {
            // TCP connect scan (nmap -sT equivalent)
            scanner.scanTCPPorts(portStart, portEnd, verbose);
        } else if (scanType == "-U") {
            // UDP scan (nmap -sU equivalent)
            scanner.scanUDPPorts(portStart, portEnd, verbose);
        } else if (scanType == "-S") {
            // Stealth/SYN scan (nmap -sS equivalent)
            scanner.scanSYNPorts(portStart, portEnd, verbose);
        }

        return 0;
    }
}