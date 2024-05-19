#pragma once
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/core.h>
#include <iostream>
#include <memory>
#include <vector>
#include <string>

struct BIO_deleter {
    void operator()(BIO* ptr) const { BIO_free_all(ptr); }
};

struct RSA_deleter {
    void operator()(RSA* ptr) const { RSA_free(ptr); }
};

struct EVP_PKEY_deleter {
    void operator()(EVP_PKEY* ptr) const { EVP_PKEY_free(ptr); }
};

class RSAManager
{
private:

public:
    RSAManager();
    ~RSAManager();

    void generate(int bits, std::string& public_key, std::string& private_key);
    std::vector<unsigned char> rsa_encrypt(const std::string& public_key, const std::string& message) ;
    std::string rsa_decrypt(const std::string& private_key, const std::vector<unsigned char>& encrypted); 
};

