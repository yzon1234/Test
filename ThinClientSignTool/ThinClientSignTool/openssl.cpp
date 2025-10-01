#include "openssl.h"


const char* displayOpenSSLVersion() {
	const char* opensslVersion = OpenSSL_version(OPENSSL_VERSION);
	return opensslVersion;
}

std::vector<unsigned char> generate_SignKey(std::vector<char> &before_Data, const std::string &private_key_path, const std::string & binary_path){
	
    // Read Pirvate Key
    FILE* key_file;
    errno_t err = fopen_s(&key_file, private_key_path.c_str(), "r");
    if (err != 0 || !key_file) {
        std::cout << "Unable to open private key file: " << private_key_path << std::endl;
        return {};
    }

    EVP_PKEY* private_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    if (!private_key) {
        std::cout << "Unable to read private key" << std::endl;
        return {};
    }
    fclose(key_file);

    // Initialize Struct
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pkey_ctx = NULL;


    // Algorithm selection
    if (EVP_DigestSignInit(md_ctx, &pkey_ctx, EVP_sha256(), NULL, private_key) <= 0) {
        std::cout << "EVP_DigestSignInit failed" << std::endl;
        EVP_MD_CTX_free(md_ctx);
        return {};
    }

    // Hashing 
    if (EVP_DigestSignUpdate(md_ctx, before_Data.data(), before_Data.size()) <= 0) {
        std::cout << "EVP_DigestSignInit failed" << std::endl;
        EVP_MD_CTX_free(md_ctx);
        return {};
    }

    // Calculate Signing hash len
    size_t signed_hash_len = 0;
    if (EVP_DigestSignFinal(md_ctx, NULL, &signed_hash_len) <= 0) {
        std::cerr << "EVP_DigestSignFinal (size calculation) failed" << std::endl;
        EVP_MD_CTX_free(md_ctx);
        return {};
    }

    // SignKey
    std::vector<unsigned char> SignKey(signed_hash_len);
    if (EVP_DigestSignFinal(md_ctx, SignKey.data(), &signed_hash_len) <= 0) {
        std::cerr << "EVP_DigestSignFinal (signing) failed" << std::endl;
        EVP_MD_CTX_free(md_ctx);
        return {};
    }

    EVP_MD_CTX_free(md_ctx);

    // Save signed file
    /*
    std::ofstream After_Sign(binary_path + ".signed", std::ios::binary);
    After_Sign.write(reinterpret_cast<char*>(SignKey.data()), signed_hash_len);
    */
    return SignKey;
}