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

namespace TCPserver
{
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

    public:
        Client(int port, std::string ipaddress);
        ~Client();

    public:
        void start();
        void init();
        void connectToServer();
        void receiveMessage();
        void sendPacket();
    };
}