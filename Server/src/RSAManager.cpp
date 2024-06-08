#include "RSAManager.h"


RSAEncryption::RSAEncryption(int keySize) {
    generateKeys(keySize);
}

RSAEncryption::~RSAEncryption() {
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
}

void RSAEncryption::generateKeys(int keySize) {
    pkey = EVP_PKEY_new();
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    if (EVP_PKEY_keygen_init(ctx) <= 0) throw std::runtime_error("EVP_PKEY_keygen_init failed");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keySize) <= 0) throw std::runtime_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) throw std::runtime_error("EVP_PKEY_keygen failed");

    publicKey = keyToString(pkey, true);
    privateKey = keyToString(pkey, false);
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
