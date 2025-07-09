#include "listener.hpp"
#include <iostream>
#include <unistd.h>
#include <thread>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>

void Listener::start() {
    if (protocol_ == "-T") {
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd == -1) {
            perror("socket");
            return;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(lport_);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(server_fd);
            return;
        }

        if (listen(server_fd, 1) < 0) {
            perror("listen");
            close(server_fd);
            return;
        }

        std::cout << "\n[*] TCP Listener on 0.0.0.0:" << lport_ << "\n";

        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) {
            perror("accept");
            close(server_fd);
            return;
        }

        std::cout << "[*] TCP connection received\n";

        std::thread recv_thread([client_fd]() {
            char buf[1024];
            while (true) {
                ssize_t n = read(client_fd, buf, sizeof(buf));
                if (n <= 0) break;
                write(STDOUT_FILENO, buf, n);
            }
        });

        char input[1024];
        while (true) {
            ssize_t n = read(STDIN_FILENO, input, sizeof(input));
            if (n <= 0) break;
            send(client_fd, input, n, 0);
        }

        recv_thread.join();
        close(client_fd);
        close(server_fd);

    } else if (protocol_ == "-U") {
        int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_sock == -1) {
            perror("socket");
            return;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(lport_);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(udp_sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(udp_sock);
            return;
        }

        std::cout << "\n[*] UDP Listener on 0.0.0.0:" << lport_ << "\n";

        char buf[1024];
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        // Wait for first message to get client info
        ssize_t n = recvfrom(udp_sock, buf, sizeof(buf), 0,
                             (sockaddr*)&client_addr, &client_len);
        if (n <= 0) {
            std::cerr << "[-] Failed to receive initial UDP packet.\n";
            close(udp_sock);
            return;
        }

        std::cout << "[*] Received UDP packet from "
                  << inet_ntoa(client_addr.sin_addr) << ":"
                  << ntohs(client_addr.sin_port) << "\n";

        // Thread to receive messages
        std::thread recv_thread([udp_sock, client_addr, client_len]() {
            char buf[1024];
            while (true) {
                ssize_t n = recvfrom(udp_sock, buf, sizeof(buf), 0,
                                     nullptr, nullptr);
                if (n <= 0) break;
                write(STDOUT_FILENO, buf, n);
            }
        });

        // Send input to client
        char input[1024];
        while (true) {
            ssize_t n = read(STDIN_FILENO, input, sizeof(input));
            if (n <= 0) break;
            sendto(udp_sock, input, n, 0,
                   (sockaddr*)&client_addr, client_len);
        }

        recv_thread.join();
        close(udp_sock);

    }
}
