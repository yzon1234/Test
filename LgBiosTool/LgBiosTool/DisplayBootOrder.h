#pragma once
#include "Meta.h"

#ifndef _DISPLAY_BOOTORDER_CONFIG_H_
#define _DISPLAY_BOOTORDER_CONFIG_H_

#define DISPLAY_BOOTORDER_CONFIG_VARIABLE_NAME "DisplayBootOrder"
#define DISPLAY_BOOTORDER_CONFIG_VARIABLE_GUID "{957AC226-C00E-4A08-BBDE-1FA9D32347B3}"
#define MAX_BOOT_ENTRIES 10
#define MAX_DESC_LEN 64

#pragma pack(push, 1)
typedef struct {
	CHAR16 BootDescriptions[MAX_BOOT_ENTRIES][MAX_DESC_LEN];
} DISPLAY_BOOTORDER;
#pragma pack(pop)

#endif  // _DISPLAY_BOOTORDER_CONFIG_H_