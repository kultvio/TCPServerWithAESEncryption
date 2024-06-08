#include "../include/Server.h"
#include "../include/RSAManager.h"
#include <iostream>
#include <vector>
#include <string>

<<<<<<< Updated upstream
int main(int argc, char** argv) 
{
    Server server(atoi(argv[2]), argv[1]);
    server.start();
=======

int main(int argc, char** argv)  {
    try {
        RSAEncryption rsaEncryption(2048);

        std::string publicKey = rsaEncryption.getPublicKey();
        std::string privateKey = rsaEncryption.getPrivateKey();

        std::cout << "Public Key:\n" << publicKey << "\n";
        std::cout << "Private Key:\n" << privateKey << "\n";

        std::string plainText = "Test Message";
        std::vector<unsigned char> plainData(plainText.begin(), plainText.end());

        // Шифруем данные
        std::vector<unsigned char> encryptedData = rsaEncryption.encrypt(plainData);
        std::cout << "Encrypted Data:\n";
        for (unsigned char byte : encryptedData) {
            std::cout << std::hex << static_cast<int>(byte);
        }
        std::cout << "\n";

        // Дешифруем данные
        std::vector<unsigned char> decryptedData = rsaEncryption.decrypt(encryptedData);
        std::string decryptedText(decryptedData.begin(), decryptedData.end());

        std::cout << "Decrypted Text:\n" << decryptedText << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
>>>>>>> Stashed changes

    return 0;
}
