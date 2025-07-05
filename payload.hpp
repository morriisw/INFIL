#pragma once
#include <vector>
#include <string>
#include <cstdint>

class LinuxX86ReverseShell {
    public:
        std::vector<uint8_t> generatePayload(const std::string& lhost, int lport);
        std::string generateCommand(const std::string& lhost, int lport);
};

class LinuxX86BindShell {
    public:
        std::vector<uint8_t> generatePayload(int lport);
        std::string generateCommand(int lport);
};