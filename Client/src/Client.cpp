 #include "Client.h"


namespace TCPserver
{
 Client::Client(int port, std::string ipaddress) : port(port), ipaddress(ipaddress), addrlength(sizeof(addr))
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

    void Client::start()
    {
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