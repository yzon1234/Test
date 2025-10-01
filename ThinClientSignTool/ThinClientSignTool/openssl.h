#pragma once
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>

const char* displayOpenSSLVersion();

std::vector<unsigned char> generate_SignKey(std::vector<char> &before_Data, const std::string &private_key_path, const std::string& binary_path);