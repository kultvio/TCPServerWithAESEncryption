#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <fstream>

#pragma once

class RSAEncryption {
public:
    RSAEncryption();
    ~RSAEncryption();
    
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data);
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& encryptedData);
    std::vector<unsigned char> sign(const std::vector<unsigned char>& data);
    std::string getPublicKey() const;
    std::string getPrivateKey() const;
    void generateKeys(int keySize);

    void saveKeysToFIle(const std::string& publicKeyFile, const std::string& privateKeyFile);
    void loadKeysFromFile(const std::string& publicKeyFile, const std::string& privateKeyFile);

    

private:
    RSA* rsa;
    EVP_PKEY* pkey;
    EVP_PKEY_CTX* ctx;

    std::string publicKey;
    std::string privateKey;

    void loadKeysFromString(const std::string& keyStr, bool isPublic);
    std::string keyToString(EVP_PKEY* pkey, bool isPublic) const;
};
