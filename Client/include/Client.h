#pragma once

#include <iostream>
#include <thread>
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <unordered_map>
#include <string>
#include <cassert>
#include "RSAManager.h"
#include "AESManager.h"

enum Packet
{
    P_ChatMessage
};

class Client
{
private:
    int Connection;
    std::string ipaddress;
    int port;
    std::string message;
    sockaddr_in addr;
    socklen_t addrlength;
    int reclength;

    bool ProcessPacket(Packet packetType);
    bool processChatMessagePacket();

    bool sendChatPacket();

    static void* ClientHandler(void* lpParam);
    RSAEncryption& rsaServer;
    AESManager aes;
    std::vector<unsigned char> key;
    bool handshake();
public:
    Client(int port, std::string ipaddress, RSAEncryption& rsaServer);
    ~Client();

public:
    void start();
    void init();
    void connectToServer();
    void receiveMessage();
    void sendPacket();
};
