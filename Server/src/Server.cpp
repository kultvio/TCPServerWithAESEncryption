#include "Server.h"
#include <algorithm>
    

Server::Server(int port, const std::string& ipaddress, Logger& logger, RSAEncryption& rsa)
    : socketManager(port, ipaddress, logger),
    packetHandler(new PacketHandler(this)),
    logger(logger),
    rsa(rsa),
    counter(0) {for (int i = 0; i < MAX_CONNECTIONS; ++i) {
        connections[i] = -1;
    }}

Server::~Server() {
}

std::vector<unsigned char> removeTrailingZeros(const std::vector<unsigned char>& vec) {
    auto it = std::find_if(vec.rbegin(), vec.rend(), [](unsigned char byte) { return byte != 0; });
    return std::vector<unsigned char>(vec.begin(), it.base());
}

std::string vectorToHexString(const std::vector<unsigned char>& data) {
    std::stringstream hexStream;

    for(unsigned char byte: data) {
        hexStream << std::hex << std::setw(2) << " " << static_cast<int>(byte);
    }

    return hexStream.str();
}

std::vector<unsigned char> Server::serializeCert(const Certificate& cert) {
    logger.log("Serializing cert");

    std::vector<unsigned char> buffer;

    auto appendData = [&](const std::vector<unsigned char>& data) {
        int size = data.size();
        buffer.insert(buffer.end(),(unsigned char*)&size,(unsigned char*)&size+ sizeof(int));
        buffer.insert(buffer.end(), data.begin(),data.end());
    };

    appendData(cert.publickey);
    appendData(cert.data);
    appendData(cert.signature);
    logger.log("cert size: " + std::to_string(buffer.size()));
    return buffer;
}

void Server::initCert() {
    logger.log("Loading public key");
    std::string publickey = rsa.getPublicKey();
    cert.publickey = std::vector<unsigned char>(publickey.begin(), publickey.end());
    std::string data = "Server name: KultCryptoCode; Certificate from: " + logger.getCurrentTIme();
    cert.data =  std::vector<unsigned char>(data.begin(), data.end());
    

    logger.log("Creating signature");
    cert.signature = rsa.sign(cert.data);
    logger.log("Cert created");
    logger.log("Cert data: " + data);

    serializedCert = serializeCert(cert);
}

void Server::start() {
    logger.log("Init socket");
    socketManager.init();
    logger.log("Complete init");
    
    logger.log("Creating cert");
    initCert();

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
            counter++;
            logger.log("Counter: " + std::to_string(counter));
            clientData = {this, i};
            std::thread(ClientHandler, &clientData).detach();
            return;
        }
    }
}
std::vector<unsigned char> Server::handshake(int clientSocket) {
    try
    {
        logger.log("Sending serialized certificate to client...");
        // Сериализуем сертификат и отправляем его целиком
        int certSize = serializedCert.size();
        // Отправляем размер и сам сериализованный буфер
        send(clientSocket, (char*)&certSize, sizeof(int), 0);
        send(clientSocket, (char*)serializedCert.data(), certSize, 0);

        logger.log("Waiting for encrypted message from client...");

        // Принимаем зашифрованное сообщение от клиента
        int is_verify;
        recv(clientSocket, (char*)&is_verify, sizeof(int), 0);
        if(is_verify != 1) {
            throw std::runtime_error("Сlient did not verify the signature");
        }

        int encryptedSize;
        recv(clientSocket, (char*)&encryptedSize, sizeof(int), 0);
        std::vector<unsigned char> encryptedMessage(encryptedSize);
        recv(clientSocket, (char*)encryptedMessage.data(), encryptedSize, 0);

        // Расшифровываем сообщение
        std::vector<unsigned char> decrypted =  rsa.decrypt(encryptedMessage);
        decrypted = removeTrailingZeros(decrypted);
    
        logger.log("AES key:" + vectorToHexString(decrypted));
        return decrypted;
    }
    catch(const std::exception& e)
    {
        logger.log(e.what(),"ERROR");
        return {'0'};
    }
    
   
    
}


void* Server::ClientHandler(void* lpParam) 
{
    ClientData* clientData = static_cast<ClientData*>(lpParam);
    Server* server = clientData->server;
    int connectionIndex = clientData->connectionIndex;
    server->logger.log("Try to handshake with client: " + std::to_string(connectionIndex));
    std::vector<unsigned char> AESkey = server->handshake(server->connections[connectionIndex]);
    if (AESkey[0] == '0') {
        close(server->connections[connectionIndex]);
        server->connections[connectionIndex] = -1;
        server->counter--;
        server->logger.log("Client with index " + std::to_string(connectionIndex) + " disconnected.");
        return nullptr;
    }
    server->AESkeys[connectionIndex] = AESkey;


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
        server->packetHandler->HandlePacket(connectionIndex, pType, AESkey);
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

std::vector<unsigned char> PacketHandler::HandlePacket(int index, PacketType pType, std::vector<unsigned char>& AESkey) {
    auto it = PacketProcessors.find(pType);
    if (it != PacketProcessors.end()) {
        return it->second->processPacket(server, index, AESkey); 
    } else {
        std::cerr << "Processor not found for the given packet type\n";
        return {'0'};
    }
}

PacketHandler::~PacketHandler()
{

}


// TEXTPACKET --------------------------------



PacketType TextPacketProcessor::pType = P_TextPacket;

std::vector<unsigned char> TextPacketProcessor::processPacket(Server* server, uint index, std::vector<unsigned char>& AESkey) {
    int msgSize;
    int bytesReceived = recv(server->getConnections()[index], (char*)&msgSize, sizeof(int), 0);
    if (bytesReceived <= 0) return {'0'};
    std::string logMessage = "Encrypted message size: " + std::to_string(msgSize);
    server->log(logMessage);
    std::vector<unsigned char> encryptedMessage(msgSize);
    recv(server->getConnections()[index], (char*)encryptedMessage.data(), msgSize, 0);

    if (bytesReceived <= 0) {

        return {'0'};
    }

    const std::string msg = server->aes.decrypt(encryptedMessage, AESkey);
    logMessage = "New Message: Index: " + std::to_string(index) + " Text:[ " + msg + " ]";
    server->log(logMessage);

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (i == index) continue;
        if (server->getConnections()[i] == -1) continue;
        encryptedMessage = server->aes.encrypt(msg, server->AESkeys[i]);
        msgSize = encryptedMessage.size();
        send(server->getConnections()[i], (char*)&pType, sizeof(pType), 0);
        send(server->getConnections()[i], (char*)&msgSize, sizeof(int), 0);
        send(server->getConnections()[i], (char*)encryptedMessage.data(), msgSize, 0);
    }
    
    return encryptedMessage;
}