#include "../include/Client.h"

int main(int argc, char** argv)
{
	TCPserver::Client client(atoi(argv[2]), argv[1]);
	client.start();
	return 0;
}
