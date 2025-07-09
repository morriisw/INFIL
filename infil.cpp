#include "scanner.hpp"
#include "payload.hpp"
#include "listener.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

using namespace std;

string invalidToolString(void) {
    return "\nPlease choose from the following tools:\n"
           "-> Scanner\n"
           "-> Payload\n"
           "-> Listener\n";
}

string correctUsageString(string tool) {
    if (tool == "scanner") {
        return "\nUsage: ./infil scanner <ip> <port> <type> [options ...]\n\n"
               "Port Options:\n"
               "-p-              Scan all ports (i.e. 1 to 65535)\n"
               "-p<portnum>      Scan a specific port (e.g. 80)\n"
               "-p<start>-<end>  Scan a range of ports (e.g. 1 to 80)\n\n"
               "Type Options:\n"
               "-T  TCP Connect Scan\n"
               "-S  Stealth/SYN Scan\n"
               "-U  UDP Scan\n\n"
               "Global Options:\n"
               "-v  Verbose Mode\n\n";
    } else if (tool == "payload") {
        return "\nUsage: ./infil payload <type> <format> [lhost] <lport>\n\n"
               "Type Options:\n"
               "-R  Reverse Shell\n"
               "-B  Bind Shell\n\n"
               "Format Options:\n"
               "-C  Shell Command\n"
               "-P  Hex Payload\n\n"
               "NOTE: lhost is not required for bind shell\n\n";
    } else if (tool == "listener") {
        return "\nUsage: ./infil listener <lport> <protocol>\n\n"
               "Protocol Options:\n"
               "-T  TCP Connection\n"
               "-U  UDP Connection\n\n";
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

int main(int argc, char* argv[]) {
    // No tool specified
    if (argc == 1) {
        std::cout << invalidToolString();
        return 1;
    }

    // Extract specified tool
    string tool = std::string(argv[1]);

    // Check for invalid tool
    if (tool != "scanner" && tool != "payload" && tool != "listener") {
        std::cout << invalidToolString();
        return 1;
    }

    // Check parameters
    if ((tool == "scanner" && (argc < 5 || argc > 6)) || 
        (tool == "payload" && (argc < 5 || argc > 6)) || 
        (tool == "listener" && (argc != 4))) {
        std::cout << correctUsageString(tool);
        return 1;
    }

    // Initialise scanner
    if (tool == "scanner") {
        string ip = argv[2];
        string portInput = argv[3];
        string scanType = argv[4];

        if (scanType != "-T" && scanType != "-S" && scanType != "-U") {
            std::cout << correctUsageString(tool);
            return 1;
        }

        Scanner scanner(ip);
        int portStart;
        int portEnd;
        bool verbose;

        // Verbose mode (include closed ports)
        verbose = (argc == 6 && std::string(argv[5]) == "-v") ? true : false;

        // Determine port/s to be scanned
        if (portInput.length() < 3 || portInput.length() > 13 || portInput.substr(0, 2) != "-p") {
            std::cout << correctUsageString(tool);
            return 1;
        } else {
            char delimiter = '-';
            vector<string> ports = splitString(portInput.substr(2, -1), delimiter);
            if (ports.size() == 1) {
                // Single port or no port number
                if (ports.at(0) != "") {
                    // Specific port number
                    try {
                        portStart = stoi(ports.at(0));
                        portEnd = stoi(ports.at(0));
                    } catch (...) {
                        std::cout << "\nInvalid port number.\n\n";
                        return 1;
                    }
                } else {
                    // Equivalent nmap -p- functionality
                    portStart = 1;
                    portEnd = 65535;
                }
            } else if (ports.size() == 2) {
                // Port range
                try {
                    portStart = stoi(ports.at(0));
                    portEnd = stoi(ports.at(1));
                } catch (...) {
                    std::cout << "\nInvalid port number.\n\n";
                    return 1;
                }
            }
        }

        if (portStart < 1 || portStart > 65535 || portEnd < 1 || portEnd > 65535) {
            std::cout << "\nPlease choose a port number between 1 and 65535 inclusive.\n\n";
            return 1;
        }

        if (portStart > portEnd) {
            std::cout << "\nStarting port number should be less than end port number.\n\n";
            return 1;
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
    } else if (tool == "payload") {
        string type = argv[2];
        string format = argv[3];

        if ((type != "-R" && type != "-B") || (format != "-C" && format != "-P")) {
            std::cout << correctUsageString(tool);
            return 1;
        }

        if (type == "-R") { // Reverse shell
            if (argc != 6) {
                std::cout << correctUsageString(tool);
                return 1;
            }

            string lhost = argv[4];
            string lport = argv[5];
            int portInt;

            // Try converting port number to integer
            try {
                portInt = std::stoi(lport);
            } catch (...) {
                std::cout << "\nInvalid port number.\n\n";
                return 1;
            }

            // Ensure port number is between 1 and 65535 
            if (portInt < 1 || portInt > 65535) {
                std::cout << "\nPlease choose a port number between 1 and 65535 inclusive.\n\n";
                return 1;
            }

            LinuxX86ReverseShell payload;

            if (format == "-C") {
                std::cout << payload.generateCommand(lhost, portInt);
                std::cout << "\n";
            } else {
                std::vector<uint8_t> hex = payload.generatePayload(lhost, portInt);
                std::cout << "\n[*] Generated shellcode (" << hex.size() << " bytes) for reverse shell:\n\n";
                for (uint8_t byte : hex)
                    printf("\\x%02x", byte);
                std::cout << "\n\n";
            }
        } else { // Bind shell
            if (argc != 5) {
                std::cout << correctUsageString(tool);
                return 1;
            }

            string lport = argv[4];
            int portInt;

            // Try converting port number to integer
            try {
                portInt = std::stoi(lport);
            } catch (...) {
                std::cout << "\nInvalid port number.\n\n";
                return 1;
            }

            // Ensure port number is between 1 and 65535 
            if (portInt < 1 || portInt > 65535) {
                std::cout << "\nPlease choose a port number between 1 and 65535 inclusive.\n\n";
                return 1;
            }

            LinuxX86BindShell payload;

            if (format == "-C") {
                std::cout << payload.generateCommand(portInt);
                std::cout << "\n";
            } else {
                std::vector<uint8_t> hex = payload.generatePayload(portInt);
                std::cout << "\n[*] Generated shellcode (" << hex.size() << " bytes) for bind shell:\n\n";
                for (uint8_t byte : hex)
                    printf("\\x%02x", byte);
                std::cout << "\n\n";
            }
        }
    } else if (tool == "listener") {
        string portInput = argv[2];
        string protocol = argv[3];
        int portInt;

        if (protocol != "-T" && protocol != "-U") {
            std::cout << correctUsageString(tool);
            return 1;
        }

        // Try converting port number to integer
        try {
            portInt = std::stoi(portInput);
        } catch (...) {
            std::cout << "\nInvalid port number.\n\n";
            return 1;
        }

        // Ensure port number is between 1 and 65535 
        if (portInt < 1 || portInt > 65535) {
            std::cout << "\nPlease choose a port number between 1 and 65535 inclusive.\n\n";
            return 1;
        }

        Listener listener(portInt, protocol);
        listener.start();
    }
}