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

EFI_STATUS EncodePassword(CHAR16* password, UINT32 PasswordLength, unsigned char* hash, unsigned int* hash_lenghth);