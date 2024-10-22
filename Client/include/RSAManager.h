#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "Logger.h"
#include <vector>
#include <string>
#include <stdexcept>
#include <fstream>

#pragma once

class RSAEncryption {
public:
    RSAEncryption(Logger& logger);
    ~RSAEncryption();
    
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data);
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& encryptedData);
    std::string getPublicKey() const;
    std::string getPrivateKey() const;
    void loadKeysFromString(const std::string& keyStr, bool isPublic);
    void generateKeys(int keySize);

    void saveKeysToFIle(const std::string& publicKeyFile, const std::string& privateKeyFile);
    void loadKeysFromFile(const std::string& publicKeyFile, const std::string& privateKeyFile);
    void loadPublicKeyFromFile(const std::string& publicKeyFile);

    std::vector<unsigned char> sign(const std::vector<unsigned char>& data);
    bool verify(const std::vector<unsigned char>& data, const std::vector<unsigned char>& signature);
    

private:
    Logger& logger;
    RSA* rsa;
    EVP_PKEY* pkey;
    EVP_PKEY_CTX* ctx;

    std::string publicKey;
    std::string privateKey;

    
    std::string keyToString(EVP_PKEY* pkey, bool isPublic) const;
};
