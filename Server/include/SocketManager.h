#pragma once
#include <arpa/inet.h>
#include <vector>
#include <string>



class SocketManager {
public:
    SocketManager(int port, const std::string& ipaddress);
    ~SocketManager();
    void init();
    int acceptConnection();
    void closeSocket(int socket);
private:
    int port;
    std::string ipaddress;
    sockaddr_in addr;
    int serversocket;
    socklen_t addrlength;
};