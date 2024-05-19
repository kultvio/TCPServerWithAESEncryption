#include "RSAManager.h"

RSAManager::RSAManager()
{

}
RSAManager::~RSAManager()
{

}
void RSAManager::generate(int bits, std::string& public_key, std::string& private_key)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if (RAND_load_file("/dev/urandom", 32) != 32) {
        std::cerr << "Error loading random data" << std::endl;
        return;
    }

    std::unique_ptr<RSA, RSA_deleter> rsa(RSA_new());
    if (!rsa) {
        std::cerr << "Error creating RSA object" << std::endl;
        return;
    }

    std::unique_ptr<BIGNUM, decltype(&BN_free)> bn(BN_new(), BN_free);
    if (!bn || !BN_set_word(bn.get(), RSA_F4)) {
        std::cerr << "Error creating BIGNUM" << std::endl;
        return;
    }

    if (!RSA_generate_key_ex(rsa.get(), bits, bn.get(), nullptr)) {
        std::cerr << "Error generating RSA keys" << std::endl;
        return;
    }

    std::unique_ptr<BIO, BIO_deleter> bio_private(BIO_new(BIO_s_mem()));
    if (!bio_private || !PEM_write_bio_RSAPrivateKey(bio_private.get(), rsa.get(), nullptr, nullptr, 0, nullptr, nullptr)) {
        std::cerr << "Error writing private key to BIO" << std::endl;
        return;
    }

    std::unique_ptr<BIO, BIO_deleter> bio_public(BIO_new(BIO_s_mem()));
    if (!bio_public || !PEM_write_bio_RSA_PUBKEY(bio_public.get(), rsa.get())) {
        std::cerr << "Error writing public key to BIO" << std::endl;
        return;
    }

    BUF_MEM* private_buf = nullptr;
    BUF_MEM* public_buf = nullptr;
    BIO_get_mem_ptr(bio_private.get(), &private_buf);
    BIO_get_mem_ptr(bio_public.get(), &public_buf);

    private_key.assign(private_buf->data, private_buf->length);
    public_key.assign(public_buf->data, public_buf->length);
}



std::vector<unsigned char> RSAManager::rsa_encrypt(const std::string& public_key, const std::string& message) {
    std::unique_ptr<BIO, BIO_deleter> bio(BIO_new_mem_buf(public_key.data(), public_key.size()));
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for public key");
    }

    std::unique_ptr<EVP_PKEY, EVP_PKEY_deleter> evp_key(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
    if (!evp_key) {
        throw std::runtime_error("Failed to read public key");
    }

    std::unique_ptr<RSA, RSA_deleter> rsa(EVP_PKEY_get1_RSA(evp_key.get()));
    if (!rsa) {
        throw std::runtime_error("Failed to get RSA from EVP_PKEY");
    }

    int rsa_len = RSA_size(rsa.get());
    int max_data_len = rsa_len - 2 * 20 - 2;  // For OAEP with SHA-1

    if (message.size() > max_data_len) {
        throw std::runtime_error("Message is too long for RSA encryption");
    }

    std::vector<unsigned char> encrypted(rsa_len);
    int len = RSA_public_encrypt(message.size(), reinterpret_cast<const unsigned char*>(message.c_str()), encrypted.data(), rsa.get(), RSA_PKCS1_OAEP_PADDING);
    if (len == -1) {
        throw std::runtime_error("Encryption failed");
    }

    encrypted.resize(len);
    return encrypted;
}

std::string RSAManager::rsa_decrypt(const std::string& private_key, const std::vector<unsigned char>& encrypted) {
    std::unique_ptr<BIO, BIO_deleter> bio(BIO_new_mem_buf(private_key.data(), private_key.size()));
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for private key");
    }

    std::unique_ptr<EVP_PKEY, EVP_PKEY_deleter> evp_key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
    if (!evp_key) {
        throw std::runtime_error("Failed to read private key");
    }

    std::unique_ptr<RSA, RSA_deleter> rsa(EVP_PKEY_get1_RSA(evp_key.get()));
    if (!rsa) {
        throw std::runtime_error("Failed to get RSA from EVP_PKEY");
    }

    std::vector<unsigned char> decrypted(RSA_size(rsa.get()));
    int len = RSA_private_decrypt(encrypted.size(), encrypted.data(), decrypted.data(), rsa.get(), RSA_PKCS1_OAEP_PADDING);
    if (len == -1) {
        throw std::runtime_error("Decryption failed");
    }

    return std::string(decrypted.begin(), decrypted.begin() + len);
}



