#include "Client.h"
#include <cstdint>
#include <cstring>

namespace TCPserver
{
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

        // Отправляем зашифрованное сообщение "OK" серверу
        std::string message = "OK";
        std::vector<unsigned char> encryptedMessage = rsaServer.encrypt(std::vector<unsigned char>(message.begin(), message.end()));

        int encryptedSize = encryptedMessage.size();
        send(Connection, (char*)&encryptedSize, sizeof(int), 0);
        send(Connection, (char*)encryptedMessage.data(), encryptedSize, 0);

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
        handshake();
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
        char* msg = new char[msgSize + 1];
        msg[msgSize] = '\0';
        recv(Connection, msg, msgSize, 0);
        std::cout << "New message: " << msg << std::endl;
        delete[] msg;
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

        std::cout << "Enter a chat message: ";
        std::string msg;
        std::getline(std::cin, msg);
        int msgSize = msg.size();
        send(Connection, &packetType, sizeof(Packet), 0);
        send(Connection, &msgSize, sizeof(int), 0);
        send(Connection, msg.c_str(), msgSize, 0);

        return true;
    }

    void Client::sendPacket()
    {
        std::cout << "\nSelect packet type: " << std::endl;
        std::cout << "1: Chat Message" << std::endl;

        int packetTypeIndex;
        std::cin >> packetTypeIndex;
        std::cin.ignore();
        packetTypeIndex--;

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
}