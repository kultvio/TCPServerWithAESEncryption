#include "../include/RSAManager.h"


RSAEncryption::RSAEncryption(Logger& logger) : pkey(nullptr), ctx(nullptr), logger(logger) {}

RSAEncryption::~RSAEncryption() {
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
}

void RSAEncryption::generateKeys(int keySize) {
    logger.log("Generate RSA keys");

    pkey = EVP_PKEY_new();
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    if (EVP_PKEY_keygen_init(ctx) <= 0) throw std::runtime_error("EVP_PKEY_keygen_init failed");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keySize) <= 0) throw std::runtime_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) throw std::runtime_error("EVP_PKEY_keygen failed");

    publicKey = keyToString(pkey, true);
    privateKey = keyToString(pkey, false);
}

std::vector<unsigned char> RSAEncryption::sign(const std::vector<unsigned char>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash);

    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if(!mdCtx) throw std::runtime_error("Failed to create signing context");

    if(EVP_SignInit(mdCtx, EVP_sha256()) <= 0) throw std::runtime_error("Error initializing the signing operation");

    if(EVP_SignUpdate(mdCtx, hash, SHA256_DIGEST_LENGTH) <= 0) throw std::runtime_error("Error updating the signing operation");

    std::vector<unsigned char> signature(EVP_PKEY_size(pkey));
    unsigned int sigLen;

    if(EVP_SignFinal(mdCtx, signature.data(), &sigLen, pkey) <= 0) throw std::runtime_error("Error finalizing the signature");

    signature.resize(sigLen); 
    EVP_MD_CTX_free(mdCtx);

    return signature;
}
bool RSAEncryption::verify(const std::vector<unsigned char>& data, const std::vector<unsigned char>& signature) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash);

    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if(!mdCtx) throw std::runtime_error("Failed to create veirfy context");

    if(EVP_VerifyInit(mdCtx, EVP_sha256()) <= 0) throw std::runtime_error("Error initializing the veirfy operation");

    if(EVP_VerifyUpdate(mdCtx, hash, SHA256_DIGEST_LENGTH) <= 0) throw std::runtime_error("Error updating the veirfy operation");

    int result =  EVP_VerifyFinal(mdCtx, signature.data(), signature.size(), pkey);
    EVP_MD_CTX_free(mdCtx);

    return result == 1;
}
void RSAEncryption::saveKeysToFIle(const std::string& publicKeyFile, const std::string& privateKeyFile) {
    std::ofstream pubOut(publicKeyFile);
    if(!pubOut) throw std::runtime_error("Failed to open public key file for writing");
    pubOut << publicKey;
    pubOut.close();

    std::ofstream privOut(privateKeyFile);
    if(!privOut) throw std::runtime_error("Falied to open private key file for writing");
    privOut << privateKey;
    privOut.close();
}

void RSAEncryption::loadKeysFromFile(const std::string& publicKeyFile, const std::string& privateKeyFile) {
    std::ifstream pubIn(publicKeyFile);
    if(!pubIn) throw std::runtime_error("Failed to open public key file for reading");
    publicKey.assign((std::istreambuf_iterator<char>(pubIn)), std::istreambuf_iterator<char>());
    pubIn.close();

    std::ifstream privIn(privateKeyFile);
    if(!privIn) throw std::runtime_error("Falied to open private key file for reading");
    privateKey.assign((std::istreambuf_iterator<char>(privIn)), std::istreambuf_iterator<char>());
    privIn.close();

    loadKeysFromString(publicKey, true);
    loadKeysFromString(privateKey, false);
}

void RSAEncryption::loadKeysFromString(const std::string& keyStr, bool isPublic) {
    BIO* bio = BIO_new_mem_buf(keyStr.data(), keyStr.size());
    if(isPublic) {
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    } else {
        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    }
    BIO_free(bio);
    if(!pkey) throw std::runtime_error("Failed to load key from string");
}

void RSAEncryption::loadPublicKeyFromFile(const std::string& publicKeyFile) {
    std::ifstream pubIn(publicKeyFile);
    if(!pubIn) throw std::runtime_error("Failed to open public key file for reading");
    publicKey.assign((std::istreambuf_iterator<char>(pubIn)), std::istreambuf_iterator<char>());
    pubIn.close();

    loadKeysFromString(publicKey, true);
}

std::string RSAEncryption::keyToString(EVP_PKEY* pkey, bool isPublic) const {
    BIO* bio = BIO_new(BIO_s_mem());
    if (isPublic) {
        PEM_write_bio_PUBKEY(bio, pkey);
    } else {
        PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    }
    
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string key(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return key;
}

std::vector<unsigned char> RSAEncryption::encrypt(const std::vector<unsigned char>& data) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new failed");

    if (EVP_PKEY_encrypt_init(ctx) <= 0) throw std::runtime_error("EVP_PKEY_encrypt_init failed");

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, data.data(), data.size()) <= 0) throw std::runtime_error("EVP_PKEY_encrypt failed");

    std::vector<unsigned char> out(outlen);
    if (EVP_PKEY_encrypt(ctx, out.data(), &outlen, data.data(), data.size()) <= 0) throw std::runtime_error("EVP_PKEY_encrypt failed");

    EVP_PKEY_CTX_free(ctx);
    return out;
}

std::vector<unsigned char> RSAEncryption::decrypt(const std::vector<unsigned char>& encryptedData) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new failed");

    if (EVP_PKEY_decrypt_init(ctx) <= 0) throw std::runtime_error("EVP_PKEY_decrypt_init failed");

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, encryptedData.data(), encryptedData.size()) <= 0) throw std::runtime_error("EVP_PKEY_decrypt failed");

    std::vector<unsigned char> out(outlen);
    if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, encryptedData.data(), encryptedData.size()) <= 0) throw std::runtime_error("EVP_PKEY_decrypt failed");

    EVP_PKEY_CTX_free(ctx);
    return out;
}

std::string RSAEncryption::getPublicKey() const {
    return publicKey;
}

std::string RSAEncryption::getPrivateKey() const {
    return privateKey;
}

