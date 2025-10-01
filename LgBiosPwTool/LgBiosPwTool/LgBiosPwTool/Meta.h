#include <Windows.h>
#include <conio.h>
#include <iostream>
#include <vector>
#include "string.h"
#include "openssl.h"
#include <fstream>
#include <iomanip>


#define CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN 16
#define EFI_STATUS UINT32

typedef unsigned __int64  UINT64;
typedef __int64           INT64;
typedef unsigned __int32  UINT32;
typedef __int32           INT32;
typedef unsigned short    UINT16;
typedef unsigned short    CHAR16;
typedef short             INT16;
typedef unsigned char     BOOLEAN;
typedef unsigned char     UINT8;
typedef char              CHAR8;
typedef signed char       INT8;

void genAdminPassword(char *oldpassword , char *newpassword);
void genAdminPassword(char* newpassword);
void genUserPassword(char* oldpassword, char* newpassword);
void genUserPassword(char* newpassword);