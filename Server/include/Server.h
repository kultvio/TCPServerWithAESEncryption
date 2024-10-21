#pragma once
#include "SocketManager.h"
#include "RSAManager.h"
#include <iostream>
#include <thread>
#include <vector>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unordered_map>
#include <string>
#include <cassert>

#define MAX_CONNECTIONS 10

class PacketHandler;

class Server {
public:
    Server(int port, const std::string& ipaddress);
    ~Server();
    void start();
    void generateCertificate();
    int loadCertificate(std::string path);
    int* getConnections();
private:
    

    void getConnect();
    static void* ClientHandler(void* lpParam);
    struct ClientData 
    {
        Server* server;
        int connectionIndex;
    };

    SocketManager socketManager;
    std::unique_ptr<PacketHandler> packetHandler;
    uint counter;
    int connections[MAX_CONNECTIONS];

    ClientData clientData;

    
};




enum PacketType
{
    P_TextPacket
};

class PacketProcessor {
public:
    virtual ~PacketProcessor() = default;
    virtual bool processPacket(Server* server, uint index) = 0;
    virtual PacketType getPacketType() = 0;
};

class PacketHandler {
private:
    Server* server;
    std::unordered_map<PacketType, std::unique_ptr<PacketProcessor>> PacketProcessors;

public:
    PacketHandler(Server* server);
    ~PacketHandler();

    void addProcessor(PacketType pType, std::unique_ptr<PacketProcessor> processor);
    bool HandlePacket(int Index, PacketType pType);
};



class TextPacketProcessor : public PacketProcessor {
private:
    static PacketType pType;

public:
    bool processPacket(Server* server, uint index) override;
    PacketType getPacketType() override { return pType; }
};
