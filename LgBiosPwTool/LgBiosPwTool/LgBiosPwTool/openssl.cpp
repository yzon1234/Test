#include "openssl.h"
#include "Meta.h"
bool
EncodePassword(CHAR16* password, UINT32 PasswordLength, unsigned char* hash, unsigned int* hash_length) {

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();


    if (EVP_DigestInit(mdctx, EVP_sha256()) <= 0) {
        EVP_MD_CTX_free(mdctx);
        std::cerr << "Failed to initialize digest context" << std::endl;
        return FALSE;
    }

    if (EVP_DigestUpdate(mdctx, (VOID*)password, (UINT32)(PasswordLength * sizeof(CHAR16))) <= 0) {
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