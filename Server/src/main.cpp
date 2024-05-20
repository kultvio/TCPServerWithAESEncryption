#include "../include/RSAManager.h"
#include "../include/AESManager.h"
#include <iostream>
#include <vector>
#include <iomanip> 

int main() {
    // RSAManager rsaManager;
    // std::string public_key;
    // std::string private_key;
    // rsaManager.generate(2048, public_key, private_key);
    // std::cout << public_key << std::endl;
    // std::cout << private_key << std::endl;
    // std::string message = "Key256bitdfsdgsdgsdgsdgsdg";
    // std::vector<unsigned char> encrypted = rsaManager.rsa_encrypt(public_key,message);
    // std::string decrypted = rsaManager.rsa_decrypt(private_key, encrypted);

    // std::cout << "plaintext: " <<  message << std::endl;

    // std::cout << "Encrypted data: ";
    // for (unsigned char byte : encrypted) {
    //     std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    // }
    // std::cout << std::dec << std::endl;

    // std::cout << "decrypted: " << decrypted << std::endl;

    // return 0;

    try {
        AESManager aes;
        std::vector<unsigned char> key = aes.generateAESKey();
        // Шифрование
        std::string plaintext = "Hello, World!";
        auto ciphertext = aes.encrypt(plaintext,key);
        std::cout << "Encrypted text (hex): ";
        for (unsigned char c : ciphertext) {
            std::cout << std::hex << static_cast<int>(c);
        }
        std::cout << std::dec << std::endl;

        // Дешифрование
        auto decryptedtext = aes.decrypt(ciphertext,key);
        std::cout << "Decrypted text: " << decryptedtext << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}
