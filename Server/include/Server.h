#pragma once
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

#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_CONNECTIONS 5

namespace TCPserver
{
	enum Packet
	{
		P_ChatMessage
	};
	class Server
	{
	private:
		int serversocket;
		int connections[MAX_CONNECTIONS];
		int counter = 0;
		std::string ipaddress;
		int port;
		std::string message;
		sockaddr_in addr;
		socklen_t addrlength;
		int reclength;

		struct ClientData {
			Server* server;
			int connectionIndex;
		};
		ClientData clientData;


	private:
		void init();
		static void* ClientHandler(void* lpParam);
		void getCconnect();
		bool processPacket(int Index, Packet packetType);
		bool processChatMessagePacket(int Index);
		void sendMessageByIndex(int Index, char* msg, int msgSize, Packet packetType);
	public:
		Server(int, std::string);
		~Server();
	public:
		void start();
		//void stop();
	};
}