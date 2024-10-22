#include "SocketManager.h"

#include <iostream>
#include <unistd.h>

SocketManager::SocketManager(int port, const std::string& ipaddress, Logger& logger)
    : port(port), ipaddress(ipaddress), addrlength(sizeof(addr)), logger(logger) {}

SocketManager::~SocketManager() {
    close(serversocket);
}

void SocketManager::init() {
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ipaddress.c_str());

    logger.log("Try to create socket");
    serversocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serversocket == -1) {
        std::cerr << "Failed to create socket." << std::endl;
        exit(EXIT_FAILURE);
    }
    logger.log("Try to bind adress");
    if (bind(serversocket, reinterpret_cast<sockaddr*>(&addr), addrlength) == -1) {
        std::cerr << "Failed to bind to address." << std::endl;
        close(serversocket);
        exit(EXIT_FAILURE);
    }
    logger.log("Try to listen socket");
    if (listen(serversocket, SOMAXCONN) == -1) {
        std::cerr << "Failed to listen on socket." << std::endl;
        close(serversocket);
        exit(EXIT_FAILURE);
    }
    logger.log("Success!");
}

int SocketManager::acceptConnection() {
    return accept(serversocket, reinterpret_cast<sockaddr*>(&addr), &addrlength);
}

void SocketManager::closeSocket(int socket) {
    close(socket);
}
