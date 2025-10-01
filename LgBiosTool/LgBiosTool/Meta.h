#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include <iostream>
#include "openssl.h"
#include <vector>
#include "string.h"

#define EFI_STATUS UINT32
#define BIOS_SECURITY_ON 1
#define DEBUG_BUILD 0
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
void Useage();