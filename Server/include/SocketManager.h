#pragma once
#include <arpa/inet.h>
#include <vector>
#include <string>
#include "Logger.h"



class SocketManager {
public:
    SocketManager(int port, const std::string& ipaddress, Logger& logger);
    ~SocketManager();
    void init();
    int acceptConnection();
    void closeSocket(int socket);
private:
    Logger& logger;
    int port;
    std::string ipaddress;
    sockaddr_in addr;
    int serversocket;
    socklen_t addrlength;
};