#include "Client.h"
#include <cstdint>
#include <cstring>


Client::Client(int port, std::string ipaddress, RSAEncryption& rsaServer) : port(port), ipaddress(ipaddress), addrlength(sizeof(addr)), rsaServer(rsaServer)
{
    // Инициализация сокета
    Connection = socket(AF_INET, SOCK_STREAM, 0);
    if (Connection == -1)
    {
        std::cerr << "Socket creation failed!" << std::endl;
        exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ipaddress.c_str(), &addr.sin_addr);
}

Client::~Client()
{
    close(Connection);
}

// Структура сертификата
struct Certificate {
    std::vector<unsigned char> publickey;
    std::vector<unsigned char> data;
    std::vector<unsigned char> signature;
};

// Десериализация буфера в структуру Certificate
Certificate deserializeCert(const std::vector<unsigned char>& buffer) {
    Certificate cert;
    size_t offset = 0;

    auto extractData = [&](std::vector<unsigned char>& target) {
        int size;
        std::memcpy(&size, buffer.data() + offset, sizeof(int));
        offset += sizeof(int);

        target.resize(size);
        std::memcpy(target.data(), buffer.data() + offset, size);
        offset += size;
    };

    extractData(cert.publickey);
    extractData(cert.data);
    extractData(cert.signature);

    return cert;
}

bool Client::handshake() {
    // Принимаем размер сертификата
    int certSize;
    recv(Connection, (char*)&certSize, sizeof(int), 0);

    // Принимаем сериализованный буфер
    std::vector<unsigned char> serializedCert(certSize);
    recv(Connection, (char*)serializedCert.data(), certSize, 0);

    // Десериализуем сертификат
    Certificate cert = deserializeCert(serializedCert);
    std::cout << "Certificate received. Verifying signature...\n";

    // Проверяем подпись
    if (!rsaServer.verify(cert.data, cert.signature)) {
        std::cerr << "Signature verification failed.\n";
        return false;
    }
    std::cout << "Signature verified successfully.\n";
    int success = 1;
    send(Connection, (char*)&success, sizeof(int), 0);
    // Отправляем зашифрованное сообщение "OK" серверу
    key = aes.generateAESKey();
    std::vector<unsigned char> encryptedKey = rsaServer.encrypt(key);

    int encryptedSize = encryptedKey.size();
    send(Connection, (char*)&encryptedSize, sizeof(int), 0);
    send(Connection, (char*)encryptedKey.data(), encryptedSize, 0);

    std::cout << "Encrypted message sent. Handshake completed.\n";
    return true;
}

void Client::start()
{
    std::cout << rsaServer.getPublicKey();
    init();
    connectToServer();
    while (true)
    {
        sendPacket();
    }
}

void Client::init()
{
    
}

void Client::connectToServer()
{
    if (connect(Connection, (sockaddr*)&addr, addrlength) != 0)
    {
        std::cerr << "Failed to connect to server!" << std::endl;
        exit(1);
    }
    if( !handshake()) {
        std::cerr << "Failed to connect to server!" << std::endl;
        close(Connection);
        exit(1);
    }
    std::cout << "Connected to Server: Success." << std::endl;
    pthread_t thread;
    pthread_create(&thread, nullptr, ClientHandler, this);
}

bool Client::ProcessPacket(Packet packetType)
{
    switch (packetType)
    {
    case P_ChatMessage:
        return processChatMessagePacket();
    default:
        return false;
    }
}

bool Client::processChatMessagePacket()
{
    int msgSize;
    recv(Connection, &msgSize, sizeof(int), 0);
    //std::string logMessage = "Encrypted message size: " + std::to_string(msgSize);
    //std::cout << logMessage << std::endl;
    std::vector<unsigned char> encryptedMessage(msgSize);
    recv(Connection, (char*)encryptedMessage.data(), msgSize, 0);

    std::string msg = aes.decrypt(encryptedMessage, key);

    std::cout << "New message: " << msg << std::endl;
    return true;
}

void* Client::ClientHandler(void* lpParam)
{
    Client* client = static_cast<Client*>(lpParam);
    while (true)
    {
        client->receiveMessage();
    }
    return nullptr;
}

void Client::receiveMessage()
{
    Packet packetType;
    recv(Connection, &packetType, sizeof(Packet), 0);
    if (!ProcessPacket(packetType))
    {
        std::cout << "Failed to receive message" << std::endl;
    }
}

bool Client::sendChatPacket()
{
    Packet packetType = P_ChatMessage;

    //std::cout << "Enter a chat message: ";
    std::string msg;
    std::getline(std::cin, msg);
    std::vector<unsigned char> encrypted = aes.encrypt(msg,key);
    int msgSize = encrypted.size();
    send(Connection, &packetType, sizeof(Packet), 0);
    send(Connection, (char*)&msgSize, sizeof(int), 0);
    send(Connection, (char*)encrypted.data(), msgSize, 0);

    return true;
}

void Client::sendPacket()
{
    // std::cout << "\nSelect packet type: " << std::endl;
    // std::cout << "1: Chat Message" << std::endl;

    int packetTypeIndex = 0;
    // std::cin >> packetTypeIndex;
    // std::cin.ignore();
    // packetTypeIndex--;

    switch (packetTypeIndex)
    {
    case P_ChatMessage:
        sendChatPacket();
        break;
    default:
        std::cout << "Unknown packet type" << std::endl;
        break;
    }
}
