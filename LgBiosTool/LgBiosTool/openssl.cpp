#include "openssl.h"

bool
EncodePassword(CHAR16* password, UINT32 PasswordLength, unsigned char* hash, unsigned int* hash_length) {

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
   

    if (EVP_DigestInit(mdctx, EVP_sha256()) <= 0) {
        EVP_MD_CTX_free(mdctx);
        std::cerr << "Failed to initialize digest context" << std::endl;
        return FALSE;
    }

    if (EVP_DigestUpdate(mdctx, (VOID *) password, (UINT32)(PasswordLength * sizeof(CHAR16))) <= 0) {
        EVP_MD_CTX_free(mdctx);
        std::cerr << "Failed to initialize digest context" << std::endl;
        return FALSE;
    }

    if (EVP_DigestFinal(mdctx, hash, hash_length) <= 0) {
        EVP_MD_CTX_free(mdctx);
        std::cerr << "Failed to initialize digest context" << std::endl;
        return FALSE;
    }

    EVP_MD_CTX_free(mdctx);
    return TRUE;
}


std::vector<unsigned char> sha256(std::vector<char> original_data) {

	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    unsigned int hash_length = 0;
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);

    if (EVP_DigestInit(mdctx, EVP_sha256()) <= 0) {
        EVP_MD_CTX_free(mdctx);
        std::cerr << "Failed to initialize digest context" << std::endl;
        return {};
    }

    if (EVP_DigestUpdate(mdctx, reinterpret_cast<const unsigned char*>(original_data.data()), original_data.size()) <=0){
        EVP_MD_CTX_free(mdctx);
        std::cerr << "Failed to initialize digest context" << std::endl;
        return {};
    }

    if (EVP_DigestFinal(mdctx, hash.data(), &hash_length) <= 0) {
        EVP_MD_CTX_free(mdctx);
        std::cerr << "Failed to initialize digest context" << std::endl;
        return {};
    }

    EVP_MD_CTX_free(mdctx);
    return hash;
}

bool verify_with_public_key(std::vector<char> &hash, std::vector<unsigned char> signature, const std::string public_key_path) {
    
    BIO* bio = BIO_new_mem_buf(public_key_pem.data(), static_cast<int>(public_key_pem.size()));
    if (!bio) {
        std::cerr << "Failed to create BIO" << std::endl;
    }

    EVP_PKEY* public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!public_key) {
        std::cerr << "Failed to parse public key from memory\n";
    }
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pkey_ctx = NULL;

    if ( EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, public_key) <= 0) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize DigestVerify.");
    }

    if ( EVP_DigestVerifyUpdate(mdctx, hash.data(), hash.size()) <=0 ) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to update DigestVerify.");
    }

    int result = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
    EVP_MD_CTX_free(mdctx);
    return result == 1;
}