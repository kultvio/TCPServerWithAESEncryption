#include "../include/RSAManager.h"



int main() {
    RSAManager rsaManager;
    std::string public_key;
    std::string private_key;
    rsaManager.generate(2048, public_key, private_key);
    std::cout << public_key << std::endl;
    
    return 0;
}
