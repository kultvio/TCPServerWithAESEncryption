#include "../include/Server.h"
#include "../include/RSAManager.h"
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>

void printError(char** argv) {
    std::cerr << "Usage: " << argv[0] << " <ip_address> <port> --command [<filename>]" << std::endl;
    std::cerr << "Commands:" << std::endl;
    std::cerr << std::setw(20) << std::left <<"--generate" <<  "- Generate RSA keys and cert" << std::endl;
    std::cerr << std::setw(20) <<  std::left <<"--load <public.pem> <private.pem>" << "- Load RSA keys and cert" << std::endl;
    
}

int main(int argc, char** argv) 
{
    if( argc < 4) {
        printError(argv);
        return 1;
    }

    std::string ipAddress = argv[1];
    int port = atoi(argv[2]);
    Server server(port, ipAddress);
    
    const char* command = argv[3];

    RSAEncryption rsa;

    if(strcmp(command, "--generate") == 0) {
        std::cout << command << std::endl;
        try
        {
            rsa.generateKeys(4096);
            rsa.saveKeysToFIle("public.pem", "private.pem");
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            return 1;
        }
        
    } else if (strcmp(command, "--load") == 0) {
        if (argc != 6) {
            std::cerr << "Usage: " << argv[0] << "--load <public.pem> <private.pem>" << std::endl;
            return 1;
        }
        const char* publicFile = argv[4];
        const char* privateFile = argv[5];
        rsa.loadKeysFromFile(publicFile, privateFile);
    } else {
        std::cerr << "Invalid command." << std::endl;
        printError(argv);
        return 1;
    }

    server.start();
    return 0;
}
