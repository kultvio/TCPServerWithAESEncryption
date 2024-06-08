#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <vector>
#include <string>
#include <stdexcept>

class RSAEncryption {
public:
    RSAEncryption(int keySize = 2048);
    ~RSAEncryption();
    
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data);
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& encryptedData);
    
    std::string getPublicKey() const;
    std::string getPrivateKey() const;

private:
    RSA* rsa;
    EVP_PKEY* pkey;
    EVP_PKEY_CTX* ctx;

    std::string publicKey;
    std::string privateKey;

    void generateKeys(int keySize);
    std::string keyToString(EVP_PKEY* pkey, bool isPublic) const;
};
