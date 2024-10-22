#include "Server.h"

Server::Server(int port, const std::string& ipaddress, Logger& logger)
    : socketManager(port, ipaddress, logger),
    packetHandler(new PacketHandler(this)),
    logger(logger),
    counter(0) {for (int i = 0; i < MAX_CONNECTIONS; ++i) {
        connections[i] = -1;
    }}

Server::~Server() {
    socketManager.~SocketManager();
}


// void Server::generateCertificate() {
//     std::cout << "[INFO] Starting cerificate generation" << std::endl;
//     RSAEncryption rsa(2048);
//     std::cout << rsa.getPublicKey().size() << std::endl;
//     std::string public_key = rsa.getPublicKey();
//     std::cout << "[INFO] Public key obtained:" << public_key << std::endl;

//     std::vector<unsigned char> key_data(public_key.begin(), public_key.end());
//     std::cout << key_data.size();
//     std::vector<unsigned char> signature = rsa.encrypt(key_data);

//     std::cout << "[INFO] Signature generated, size: " << signature.size() << " bytes" << std::endl;
//     std::string cert = "-----BEGIN CERTIFICATE-----\n";
//     cert += "PublicKey: " + public_key + "\n";
//     cert += "Signature: " + std::string(signature.begin(), signature.end()); + "\n";
//     cert += "-----END CERTIFICATE-----\n";

//     std::cout << "[INFO] Certificate generation completed \n" << cert << std::endl;
// }

void Server::start() {
    socketManager.init();
    logger.log("Complete init");
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
        logger.log("Error: accept connetion -1");
        return;
    }
    for(int i = 0; i < MAX_CONNECTIONS; i++)
    {
        if(connections[i] == -1)
        {
            connections[i] = newConnection;
            logger.log("Client connected!");

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

    server->logger.log("Handling client with index: " + std::to_string(connectionIndex));
    PacketType pType;
    while (true)
    {
        int bytesReceived = recv(server->connections[connectionIndex], (char*)&pType, sizeof(PacketType), 0);
        if (bytesReceived <= 0)
        {
            close(server->connections[connectionIndex]);
            server->connections[connectionIndex] = -1;
            server->counter--;
            server->logger.log("Client with index " + std::to_string(connectionIndex) + " disconnected.");
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
    std::string logMessage = "New Message: Index: " + std::to_string(index) + " Message Size: " + std::to_string(msgSize)  + " Text:[ " + msg + " ]";
    server->log(logMessage);

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