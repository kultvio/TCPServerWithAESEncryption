#include "../include/Server.h"

int main(int argc, char** argv) 
{
    Server server(atoi(argv[2]), argv[1]);
    server.start();

    return 0;
}

