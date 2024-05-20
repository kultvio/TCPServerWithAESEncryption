#include "../include/Client.h"

int main(int argc, char** argv)
{
	TCPserver::Client client(8288, "127.0.0.1");
	client.start();
	return 0;
}