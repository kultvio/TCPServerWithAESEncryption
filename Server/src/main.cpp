#include "../include/Server.h"

int main(int argc, char** argv) 
{
    TCPserver::Server server(8288, "127.0.0.1");
    server.start();

    return 0;
}

