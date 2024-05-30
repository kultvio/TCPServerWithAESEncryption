#include "Server.h"

Server::Server(int port, const std::string& ipaddress)
    : socketManager(port, ipaddress),
    packetHandler(new PacketHandler(this)),
    counter(0) {for (int i = 0; i < MAX_CONNECTIONS; ++i) {
        connections[i] = -1;
    }}

Server::~Server() {
    socketManager.~SocketManager();
}

void Server::start() {
    socketManager.init();
    std::cout << "Complete init" << std::endl;
    while (true)
    {
        getConnect();
    }
    
}

void Server::getConnect() 
{
    while (counter >= MAX_CONNECTIONS) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    int newConnection = socketManager.acceptConnection();
    if(newConnection == -1)
    {
        std::cerr << "Error: accept connetion -1";
        return;
    }
    for(int i = 0; i < MAX_CONNECTIONS; i++)
    {
        if(connections[i] == -1)
        {
            connections[i] = newConnection;
            std::cout << "Client connected! \n";

            clientData = {this, i};
            std::thread(ClientHandler, &clientData).detach();
            return;
        }
    }
}

void* Server::ClientHandler(void* lpParam) 
{
    ClientData* clientData = static_cast<ClientData*>(lpParam);
    Server* server = clientData->server;
    int connectionIndex = clientData->connectionIndex;
    std::cout << "Handling client with index: " << connectionIndex << std::endl;

    PacketType pType;
    while (true)
    {
        int bytesReceived = recv(server->connections[connectionIndex], (char*)&pType, sizeof(PacketType), 0);
        if (bytesReceived <= 0)
        {
            close(server->connections[connectionIndex]);
            server->connections[connectionIndex] = -1;
            server->counter--;
            std::cout << "\nClient with index " << connectionIndex << " disconnected. \n";
            return nullptr;
        }
        server->packetHandler->HandlePacket(connectionIndex,pType);
    }
    return nullptr;
}

int* Server::getConnections()
{
    return connections;
}


PacketHandler::PacketHandler(Server* server) {
    this->server = server;
    addProcessor(PacketType::P_TextPacket, std::make_unique<TextPacketProcessor>());
}

void PacketHandler::addProcessor(PacketType pType, std::unique_ptr<PacketProcessor> processor) {
    PacketProcessors.emplace(pType, std::move(processor));
}

bool PacketHandler::HandlePacket(int index, PacketType pType) {
    auto it = PacketProcessors.find(pType);
    if (it != PacketProcessors.end()) {
        return it->second->processPacket(server, index); 
    } else {
        std::cerr << "Processor not found for the given packet type\n";
        return false;
    }
}

PacketHandler::~PacketHandler()
{

}






// TEXTPACKET --------------------------------



PacketType TextPacketProcessor::pType = P_TextPacket;

bool TextPacketProcessor::processPacket(Server* server, uint index) {
    int msgSize;
    int bytesReceived = recv(server->getConnections()[index], (char*)&msgSize, sizeof(int), 0);
    if (bytesReceived <= 0) return false;

    char* msg = new char[msgSize + 1];
    msg[msgSize] = '\0';
    bytesReceived = recv(server->getConnections()[index], msg, msgSize, 0);
    if (bytesReceived <= 0) {
        delete[] msg;
        return false;
    }

    std::cout << "\nNew Message:\n"
              << "Index: " << index << "\n"
              << "Message Size: " << msgSize << "\n"
              << "Text:\n[ " << msg << " ]\n";

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (i == index) continue;
        if (server->getConnections()[i] == -1) continue;
        send(server->getConnections()[i], (char*)&pType, sizeof(pType), 0);
        send(server->getConnections()[i], (char*)&msgSize, sizeof(int), 0);
        send(server->getConnections()[i], msg, msgSize, 0);
    }
    
    delete[] msg;
    return true;
}