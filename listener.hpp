#pragma once
#include <string>

class Listener {
    public:
        Listener(int lport, const std::string& protocol) {
            lport_ = lport;
            protocol_ = protocol;
        }

        void start();

    private:
        int lport_;
        std::string protocol_;
};
