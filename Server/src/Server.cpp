#include "Server.h"
#include <arpa/inet.h>

TCPserver::Server::Server(int port, std::string ipaddress)
{
    this->port = port;
    this->ipaddress = ipaddress;
    addrlength = sizeof(addr);
    for (int i = 0; i < MAX_CONNECTIONS; i++) connections[i] = -1;
}

TCPserver::Server::~Server()
{
}

void TCPserver::Server::start()
{
    init();
    while (true)
    {
        getCconnect();
    }
}

void TCPserver::Server::init()
{
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ipaddress.c_str());

    serversocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serversocket == -1)
    {
        std::cerr << "Failed to create socket." << std::endl;
        exit(EXIT_FAILURE);
    }

    if (bind(serversocket, (sockaddr*)&addr, addrlength) == -1)
    {
        std::cerr << "Failed to bind to address." << std::endl;
        close(serversocket);
        exit(EXIT_FAILURE);
    }

    if (listen(serversocket, SOMAXCONN) == -1)
    {
        std::cerr << "Failed to listen on socket." << std::endl;
        close(serversocket);
        exit(EXIT_FAILURE);
    }
}

void TCPserver::Server::getCconnect()
{
    while (counter >= MAX_CONNECTIONS) std::this_thread::sleep_for(std::chrono::seconds(5));

    int newConnection = accept(serversocket, (sockaddr*)&addr, &addrlength);
    if (newConnection == -1)
    {
        std::cerr << "Error to connect" << std::endl;
    }
    else
    {
        for (int i = 0; i < MAX_CONNECTIONS; i++)
        {
            if (connections[i] == -1)
            {
                connections[i] = newConnection;
                std::cout << "Client connected! \n";
                clientData = { this, i };
                std::thread(ClientHandler, &clientData).detach();
                counter++;
                break;
            }
        }
    }
}

bool TCPserver::Server::processPacket(int Index, Packet packetType)
{
    switch (packetType)
    {
    case P_ChatMessage:
        if (!processChatMessagePacket(Index)) return false;
        break;
    default:
        return false;
        break;
    }

    return true;
}

bool TCPserver::Server::processChatMessagePacket(int Index)
{
    int msgSize;
    int bytesReceived = recv(connections[Index], (char*)&msgSize, sizeof(int), 0);
    if (bytesReceived <= 0) return false;

    char* msg = new char[msgSize + 1];
    msg[msgSize] = '\0';
    recv(connections[Index], msg, msgSize, 0);

    std::cout << "\nNew Message:\n"
              << "Index: " << Index << "\n"
              << "Message Size: " << msgSize << "\n"
              << "Text:\n[ " << msg << " ]\n";

    for (int i = 0; i < MAX_CONNECTIONS; i++)
    {
        if (i == Index) continue;
        sendMessageByIndex(i, msg, msgSize, P_ChatMessage);
    }
    delete[] msg;
    return true;
}

void TCPserver::Server::sendMessageByIndex(int Index, char* msg, int msgSize, Packet packetType)
{
    if (connections[Index] == -1) return;
    send(connections[Index], (char*)&packetType, sizeof(Packet), 0);
    send(connections[Index], (char*)&msgSize, sizeof(int), 0);
    send(connections[Index], msg, msgSize, 0);
}

void* TCPserver::Server::ClientHandler(void* lpParam)
{
    ClientData* clientData = static_cast<ClientData*>(lpParam);
    Server* server = clientData->server;
    int connectionIndex = clientData->connectionIndex;
    std::cout << "Handling client with index: " << connectionIndex << std::endl;

    Packet packetType;
    while (true)
    {
        int bytesReceived = recv(server->connections[connectionIndex], (char*)&packetType, sizeof(Packet), 0);
        if (bytesReceived <= 0)
        {
            close(server->connections[connectionIndex]);
            server->connections[connectionIndex] = -1;
            server->counter--;
            std::cout << "\nClient with index " << connectionIndex << " disconnected. \n";
            return nullptr;
        }
        if (!server->processPacket(connectionIndex, packetType)) return nullptr;
    }

    return nullptr;
}
