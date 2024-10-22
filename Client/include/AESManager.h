#pragma once
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <string>
#include <iostream>
#include <stdexcept>

class AESManager
{
private:
    std::vector<unsigned char> encryptAES(const std::string& plaintext, const std::vector<unsigned char>& key);
    std::string decryptAES(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key);

public:
    std::vector<unsigned char> generateAESKey(int keyLength = 32);

    std::vector<unsigned char> encrypt(const std::string& plaintext, std::vector<unsigned char>& key) {
        return encryptAES(plaintext, key);
    }

    std::string decrypt(const std::vector<unsigned char>& ciphertext, std::vector<unsigned char>& key) {
        return decryptAES(ciphertext, key);
    }
    AESManager();
    ~AESManager();
};

