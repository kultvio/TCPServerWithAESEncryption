#include "../include/Client.h"
#include "../include/RSAManager.h"
#include "../include/Logger.h"

int main(int argc, char** argv)
{
	Logger logger;
	RSAEncryption rsa(logger);
	const char* publicFile = argv[3];
	rsa.loadPublicKeyFromFile(publicFile);
	
	Client client(atoi(argv[2]), argv[1], rsa);
	client.start();
	return 0;
}
