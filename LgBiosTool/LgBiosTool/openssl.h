#pragma once
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include "Meta.h"
const char* displayOpenSSLVersion();
std::vector<unsigned char> sha256(std::vector<char> original_data);
bool verify_with_public_key(std::vector<char> &hash, std::vector<unsigned char> signature, const std::string public_key_path);
EFI_STATUS EncodePassword(CHAR16* password, UINT32 PasswordLength, unsigned char* hash, unsigned int* hash_lenghth);
const std::string public_key_pem = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAonS9L4HUAcCXLWTKcrOr
3hhbgomYqkJeuGz5ETnIyeC1Cxx4jd5Z/TFZeUojOYIiwEQTVVUezlWBN54wZ017
vYt59HoVGy3wll+D7+5Nr0ttZQDrdebniQyAGvtlpX9+P5qMsbGyCABxO7lMeUJT
DJFVmnsgI6HBHzD9+EYRXq9/CdXCIA1r/X0x5rx5QRN4iJNMl3Efvw+uUi3cr34D
j0sUmkwVjcz7Vo4N4POW2xQ50kLXA9Mrh0TBEqWCmt6kAk9cczPOcJBsMO98N9by
FNm8VKUl3lGgRVmkd1Y8SC8uANfJ1tiuaHf1dtpe77MHaomcViFEwRcC4azHBKQ/
bQIDAQAB
-----END PUBLIC KEY-----)";