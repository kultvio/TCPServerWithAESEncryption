#include "SocketManager.h"
#include <iostream>
#include <unistd.h>

SocketManager::SocketManager(int port, const std::string& ipaddress)
    : port(port), ipaddress(ipaddress), addrlength(sizeof(addr)) {}

SocketManager::~SocketManager() {
    close(serversocket);
}

void SocketManager::init() {
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ipaddress.c_str());

    std::cout << "Try to create socket" << std::endl;
    serversocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serversocket == -1) {
        std::cerr << "Failed to create socket." << std::endl;
        exit(EXIT_FAILURE);
    }
    std::cout << "Try to bind adress"<< std::endl;
    if (bind(serversocket, reinterpret_cast<sockaddr*>(&addr), addrlength) == -1) {
        std::cerr << "Failed to bind to address." << std::endl;
        close(serversocket);
        exit(EXIT_FAILURE);
    }
    std::cout << "Try to listen socket" << std::endl;
    if (listen(serversocket, SOMAXCONN) == -1) {
        std::cerr << "Failed to listen on socket." << std::endl;
        close(serversocket);
        exit(EXIT_FAILURE);
    }
    std::cout << "Success!" << std::endl;
}

int SocketManager::acceptConnection() {
    return accept(serversocket, reinterpret_cast<sockaddr*>(&addr), &addrlength);
}

void SocketManager::closeSocket(int socket) {
    close(socket);
}
