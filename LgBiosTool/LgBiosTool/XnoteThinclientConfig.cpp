#include "XnoteThinclientConfig.h"


XNOTE_THINCLIENT_CONFIG ReadThin(){
	XNOTE_THINCLIENT_CONFIG XnoteThinVar = {0};

	//HANDLE hToken;
	DWORD pBufferSize;
	BYTE readbuf[sizeof(XNOTE_THINCLIENT_CONFIG)] = { 0, };
	// if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	// {
	// 	std::cout << "Fail to OpenProcessToken" << std::endl;
	// }

	// LUID luid;
	// LookupPrivilegeValue(NULL, SE_SYSTEM_ENVIRONMENT_NAME, &luid);

	// TOKEN_PRIVILEGES tkp;
	// tkp.PrivilegeCount = 1;
	// tkp.Privileges[0].Luid = luid;
	// tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// if (AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0) == 0)
	// {
	// 	std::cout << "Fail_To_AdjustTokenPrivileges" << std::endl;
	// }

	pBufferSize = GetFirmwareEnvironmentVariable(XNOTE_THINCLIENT_CONFIG_VARIABLE_NAME, XNOTE_THINCLIENT_CONFIG_VARIABLE_GUID, readbuf, sizeof(XNOTE_THINCLIENT_CONFIG));
	if (pBufferSize == 0) {
		std::cout << ("Failed to get the variable : %d \n", GetLastError());
	}

	memcpy(&XnoteThinVar, readbuf, sizeof(XNOTE_THINCLIENT_CONFIG));

	return XnoteThinVar;
}
bool PrintThin(bool print) {
	XNOTE_THINCLIENT_CONFIG* XnoteThinVar = NULL;

	//HANDLE hToken;
	DWORD pBufferSize;
	BYTE readbuf[sizeof(XNOTE_THINCLIENT_CONFIG)] = { 0, };
	// if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	// {
	// 	std::cout << "Fail to OpenProcessToken" << std::endl;
	// }

	// LUID luid;
	// LookupPrivilegeValue(NULL, SE_SYSTEM_ENVIRONMENT_NAME, &luid);

	// TOKEN_PRIVILEGES tkp;
	// tkp.PrivilegeCount = 1;
	// tkp.Privileges[0].Luid = luid;
	// tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// if (AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0) == 0)
	// {
	// 	std::cout << "Fail_To_AdjustTokenPrivileges" << std::endl;
	// }

	pBufferSize = GetFirmwareEnvironmentVariable(XNOTE_THINCLIENT_CONFIG_VARIABLE_NAME, XNOTE_THINCLIENT_CONFIG_VARIABLE_GUID, readbuf, sizeof(XNOTE_THINCLIENT_CONFIG));
	if (pBufferSize == 0) {
		std::cout << ("Failed to get the variable : ") << GetLastError() << std::endl;;
		return FALSE;
	}
    if(print)
	{
	  XnoteThinVar = (XNOTE_THINCLIENT_CONFIG *)readbuf;

	  std::cout << ("=========== Device Info ==========") << std::endl;
	  std::cout << ("WlanEnable      : ") << XnoteThinVar->ThinWlanEnable << std::endl;
	  std::cout << ("BluetoothEnable : ") << XnoteThinVar->ThinBluetoothEnable << std::endl;
	  std::cout << ("MicroSdEnable   : ") << XnoteThinVar->ThinMicroSdEnable << std::endl;
	  std::cout << ("WebcamEnable    : ") << XnoteThinVar->ThinWebcamEnable << std::endl;
	  std::cout << ("UsbPortEnable   : ") << XnoteThinVar->ThinUsbPortEnable << std::endl;
	  std::cout << ("UsbPort1        : ") << XnoteThinVar->ThinUsbPerPort[0] << std::endl;
	  std::cout << ("UsbPort2        : ") << XnoteThinVar->ThinUsbPerPort[1] << std::endl;
	  std::cout << ("UsbPort3        : ") << XnoteThinVar->ThinUsbPerPort[2] << std::endl;
	  std::cout << ("UsbPort4        : ") << XnoteThinVar->ThinUsbPerPort[3] << std::endl;
	  std::cout << ("UsbPort5        : ") << XnoteThinVar->ThinUsbPerPort[4] << std::endl;
	  std::cout << ("UsbPort6        : ") << XnoteThinVar->ThinUsbPerPort[5] << std::endl;
	  std::cout << ("UsbPort7        : ") << XnoteThinVar->ThinUsbPerPort[6] << std::endl;
	  std::cout << ("UsbBootEnable   : ") << XnoteThinVar->ThinUsbBootEnable << std::endl;
	  std::cout << ("PxeBoot         : ") << XnoteThinVar->ThinNetworkStack << std::endl;
	  std::cout << ("WolEnable       : ") << XnoteThinVar->ThinWolEnable << std::endl;
	  std::cout << ("LastPowerState  : ") << XnoteThinVar->ThinLastPowerState << std::endl;
	  std::cout << ("==================================") << std::endl;
	}
	return TRUE;
}

void SaveThin(){

	XNOTE_THINCLIENT_CONFIG XnoteThinVar = {0};
	XnoteThinVar = ReadThin();

	FILE *fp = fopen("Bios_Config.txt", "a+");
			
	if (fp == NULL) {
	  std::cout << ("Failed to open file") << std::endl;
	  return;
	}
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    if (file_size == 0) {
		rewind(fp);
		fprintf(fp, "==== BIOS CONFIG ====\n");
		fprintf(fp, "WlanEnable      : %d\n", XnoteThinVar.ThinWlanEnable);
		fprintf(fp, "BluetoothEnable : %d\n", XnoteThinVar.ThinBluetoothEnable);
		fprintf(fp, "MicroSdEnable   : %d\n", XnoteThinVar.ThinMicroSdEnable);
		fprintf(fp, "WebcamEnable    : %d\n", XnoteThinVar.ThinWebcamEnable);
		fprintf(fp, "UsbPortEnable   : %d\n", XnoteThinVar.ThinUsbPortEnable);
		fprintf(fp, "UsbBootEnable   : %d\n", XnoteThinVar.ThinUsbBootEnable);
		fprintf(fp, "PxeBoot         : %d\n", XnoteThinVar.ThinNetworkStack);
		fprintf(fp, "WolEnable       : %d\n", XnoteThinVar.ThinWolEnable);
		fprintf(fp, "LastPowerState  : %d\n", XnoteThinVar.ThinLastPowerState);
		fprintf(fp, "UsbPort1        : %d\n", XnoteThinVar.ThinUsbPerPort[0]);
		fprintf(fp, "UsbPort2        : %d\n", XnoteThinVar.ThinUsbPerPort[1]);
		fprintf(fp, "UsbPort3        : %d\n", XnoteThinVar.ThinUsbPerPort[2]);
		fprintf(fp, "UsbPort4        : %d\n", XnoteThinVar.ThinUsbPerPort[3]);
		fprintf(fp, "UsbPort5        : %d\n", XnoteThinVar.ThinUsbPerPort[4]);
		fprintf(fp, "UsbPort6        : %d\n", XnoteThinVar.ThinUsbPerPort[5]);
		fprintf(fp, "UsbPort7        : %d\n", XnoteThinVar.ThinUsbPerPort[6]);
    }
    
    char configPath[MAX_PATH] = {0};
    DWORD len = GetFullPathNameA("bios_config.txt", MAX_PATH, configPath, nullptr);

	fclose(fp);
    std::cout << ("The changes have been successfully saved in ") << configPath << std::endl;
	return;
}
void LoadThin(){
	XNOTE_THINCLIENT_CONFIG XnoteThinVar = {0};	
    char line[100];
	EFI_STATUS Status;
	BYTE readbuf[sizeof(XNOTE_THINCLIENT_CONFIG)] = { 0, };
	XnoteThinVar = ReadThin();
	memcpy(readbuf, &XnoteThinVar, sizeof(XnoteThinVar));
	
	FILE *fp = fopen("Bios_Config.txt", "r");
			
	char key[50];
	int value;
	
	if (fp == NULL) {
	  std::cout << ("Please Save File First") << std::endl;
	  return;
	}


	while (fgets(line, sizeof(line), fp)) {
	  if (sscanf(line, " %49[^: \t] %*[: \t] %d", key, &value) == 2) {
	  	if (_stricmp(key, "WlanEnable") == 0) {
	  		XnoteThinVar.ThinWlanEnable = value;
	  	} else if (_stricmp(key, "BluetoothEnable") == 0) {
	  		XnoteThinVar.ThinBluetoothEnable = value;
	  	} else if (_stricmp(key, "MicroSdEnable") == 0) {
	  		XnoteThinVar.ThinMicroSdEnable = value;
	  	} else if (_stricmp(key, "WebcamEnable") == 0) {
	  		XnoteThinVar.ThinWebcamEnable = value;
	  	} else if (_stricmp(key, "UsbPortEnable") == 0) {
	  		XnoteThinVar.ThinUsbPortEnable = value;
	  	} else if (_stricmp(key, "UsbBootEnable") == 0) {
	  		XnoteThinVar.ThinUsbBootEnable = value;
	  	} else if (_stricmp(key, "LastPowerState") == 0) {
	  		XnoteThinVar.ThinLastPowerState = value;
	  	} else if (_stricmp(key, "WolEnable") == 0) {
	  		XnoteThinVar.ThinWolEnable = value;
	  	} else if (_stricmp(key, "PxeBoot") == 0) {
	  		XnoteThinVar.ThinNetworkStack = value;
	  	} else if (_stricmp(key, "UsbPort1") == 0) {
	  		XnoteThinVar.ThinUsbPerPort[0] = value;
	  	} else if (_stricmp(key, "UsbPort2") == 0) {
			XnoteThinVar.ThinUsbPerPort[1] = value;
		} else if (_stricmp(key, "UsbPort3") == 0) {
			XnoteThinVar.ThinUsbPerPort[2] = value;
		} else if (_stricmp(key, "UsbPort4") == 0) {
			XnoteThinVar.ThinUsbPerPort[3] = value;
		} else if (_stricmp(key, "UsbPort5") == 0) {
			XnoteThinVar.ThinUsbPerPort[4] = value;
		} else if (_stricmp(key, "UsbPort6") == 0) {
			XnoteThinVar.ThinUsbPerPort[5] = value;
		} else if (_stricmp(key, "UsbPort7") == 0) {
			XnoteThinVar.ThinUsbPerPort[6] = value;
		}
	  }
	}
		
	fclose(fp);
    
    memcpy(readbuf, &XnoteThinVar, sizeof(XnoteThinVar));

	std::cout << ("==== BIOS CONFIG ====\n");
	std::cout << ("WlanEnable      : ") << XnoteThinVar.ThinWlanEnable << std::endl;
	std::cout << ("BluetoothEnable : ") << XnoteThinVar.ThinBluetoothEnable << std::endl;
	std::cout << ("MicroSdEnable   : ") << XnoteThinVar.ThinMicroSdEnable << std::endl;
	std::cout << ("WebcamEnable    : ") << XnoteThinVar.ThinWebcamEnable << std::endl;
	std::cout << ("UsbPortEnable   : ") << XnoteThinVar.ThinUsbPortEnable << std::endl;
	std::cout << ("UsbBootEnable   : ") << XnoteThinVar.ThinUsbBootEnable << std::endl;
	std::cout << ("PxeBoot         : ") << XnoteThinVar.ThinNetworkStack << std::endl;
	std::cout << ("WolEnable       : ") << XnoteThinVar.ThinWolEnable << std::endl;
	std::cout << ("LastPowerState  : ") << XnoteThinVar.ThinLastPowerState << std::endl;
	std::cout << ("UsbPerPort[1]   : ") << XnoteThinVar.ThinUsbPerPort[0] << std::endl;
	std::cout << ("UsbPerPort[2]   : ") << XnoteThinVar.ThinUsbPerPort[1] << std::endl;
	std::cout << ("UsbPerPort[3]   : ") << XnoteThinVar.ThinUsbPerPort[2] << std::endl;
	std::cout << ("UsbPerPort[4]   : ") << XnoteThinVar.ThinUsbPerPort[3] << std::endl;
	std::cout << ("UsbPerPort[5]   : ") << XnoteThinVar.ThinUsbPerPort[4] << std::endl;
	std::cout << ("UsbPerPort[6]   : ") << XnoteThinVar.ThinUsbPerPort[5] << std::endl;
	std::cout << ("UsbPerPort[7]   : ") << XnoteThinVar.ThinUsbPerPort[6] << std::endl;

	
	Status = SetFirmwareEnvironmentVariable(XNOTE_THINCLIENT_CONFIG_VARIABLE_NAME, XNOTE_THINCLIENT_CONFIG_VARIABLE_GUID, readbuf, sizeof(XNOTE_THINCLIENT_CONFIG));
	if (Status == 0) {
		std::cout << ("Failed to set the variable : %d \n", GetLastError());
	}
	std::cout << ("The changes have been successfully applied.") << std::endl;	
}

void WriteSecurityKey(std::vector<unsigned char>& hash, std::vector<unsigned char>& signature) {
#if BIOS_SECURITY_ON
	EFI_STATUS Status;
	XNOTE_THINCLIENT_CONFIG* XnoteThinVar = NULL;
	BYTE readbuf[sizeof(XNOTE_THINCLIENT_CONFIG)] = { 0, };
	DWORD pBufferSize;

	pBufferSize = GetFirmwareEnvironmentVariable(XNOTE_THINCLIENT_CONFIG_VARIABLE_NAME, XNOTE_THINCLIENT_CONFIG_VARIABLE_GUID, readbuf, sizeof(XNOTE_THINCLIENT_CONFIG));
	if (pBufferSize == 0) {
		std::cout << ("Failed to get the variable : %d \n", GetLastError());
	}

	XnoteThinVar = (XNOTE_THINCLIENT_CONFIG*)readbuf;

	memcpy(XnoteThinVar->ThinHash, hash.data(), hash.size());
	memcpy(XnoteThinVar->ThinSingKey, signature.data(), signature.size());

#if DEBUG_BUILD
	for (size_t i = 0; i < 32; i++) {
		printf("%02x ", XnoteThinVar->ThinHash[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n");

	for (size_t i = 0; i < 256; i++) {
		printf("%02x ", XnoteThinVar->ThinSingKey[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
#endif

	Status = SetFirmwareEnvironmentVariable(XNOTE_THINCLIENT_CONFIG_VARIABLE_NAME, XNOTE_THINCLIENT_CONFIG_VARIABLE_GUID, readbuf, sizeof(XNOTE_THINCLIENT_CONFIG));
	if (Status == 0) {
		std::cout << ("Failed to set the variable : %d \n", GetLastError());
	}
#endif
}

void WriteThin(char *argv1,char *argv2){
    EFI_STATUS Status;
	XNOTE_THINCLIENT_CONFIG *XnoteThinVar = NULL;
	BYTE readbuf[sizeof(XNOTE_THINCLIENT_CONFIG)] = { 0, };
    DWORD pBufferSize;
	
	pBufferSize = GetFirmwareEnvironmentVariable(XNOTE_THINCLIENT_CONFIG_VARIABLE_NAME, XNOTE_THINCLIENT_CONFIG_VARIABLE_GUID, readbuf, sizeof(XNOTE_THINCLIENT_CONFIG));
	if (pBufferSize == 0) {
		std::cout << ("Failed to get the variable : %d \n", GetLastError());
	}

	XnoteThinVar = (XNOTE_THINCLIENT_CONFIG *)readbuf;
	UINT8 WriteValue = 0;
	if (_stricmp(argv1, "enable") == 0 ){
		WriteValue = 1;
	}
	else if (_stricmp(argv1, "disable") == 0 ){
		WriteValue = 0;
	}
    else if (_stricmp(argv1, "bootorder") == 0) {
        int len = strlen(argv2);
        int maxLen = 9;
        for (int i = 0; i < len && i < maxLen; i++) {
          XnoteThinVar->ThinBootPriority[i] = argv2[i];
        }
        
		std::cout << ("Next Boot will : ");
		for (int i = 0; i < len && i < maxLen; i++) {
			std::cout <<  static_cast<char>(XnoteThinVar->ThinBootPriority[i]);
		}
		std::cout << std::endl;
		std::cout << ("The changes have been successfully applied.") << std::endl;
		return;
    }


    if(_stricmp(argv2, "WlanEnable") == 0){
      XnoteThinVar->ThinWlanEnable = WriteValue;
	}
	else if(_stricmp(argv2, "BluetoothEnable") == 0){
	  XnoteThinVar->ThinBluetoothEnable = WriteValue;
	}

	else if(_stricmp(argv2, "MicroSdEnable") == 0){
	  XnoteThinVar->ThinMicroSdEnable = WriteValue;
	}
	else if(_stricmp(argv2, "WebcamEnable") == 0){
	  XnoteThinVar->ThinWebcamEnable = WriteValue;
	}

	else if(_stricmp(argv2, "UsbPortEnable") == 0){
		XnoteThinVar->ThinUsbPortEnable = WriteValue;
	}

	else if(_stricmp(argv2, "UsbBootEnable") == 0){
		XnoteThinVar->ThinUsbBootEnable = WriteValue;
	}

	else if(_stricmp(argv2, "LastPowerState") == 0){
		if(XnoteThinVar->ThinHaveBattery == 0){
		  XnoteThinVar->ThinLastPowerState = WriteValue;
		}
		else{
		  std::cout << ("This model does not support LastPowerState") << std::endl;
		}
	}

	else if(_stricmp(argv2, "PxeBoot") == 0){
		XnoteThinVar->ThinNetworkStack = WriteValue;
	}
    
	else if (_stricmp(argv2, "UsbPort1") == 0) {
		XnoteThinVar->ThinUsbPerPort[0] = WriteValue;
	}

	else if (_stricmp(argv2, "UsbPort2") == 0) {
		XnoteThinVar->ThinUsbPerPort[1] = WriteValue;
	}

	else if (_stricmp(argv2, "UsbPort3") == 0) {
		XnoteThinVar->ThinUsbPerPort[2] = WriteValue;
	}

	else if (_stricmp(argv2, "UsbPort4") == 0) {
		XnoteThinVar->ThinUsbPerPort[3] = WriteValue;
	}

	else if (_stricmp(argv2, "UsbPort5") == 0) {
		XnoteThinVar->ThinUsbPerPort[4] = WriteValue;
	}

	else if (_stricmp(argv2, "UsbPort6") == 0) {
		XnoteThinVar->ThinUsbPerPort[5] = WriteValue;
	}

	else{
		Useage();
		return;
	}

	Status = SetFirmwareEnvironmentVariable(XNOTE_THINCLIENT_CONFIG_VARIABLE_NAME, XNOTE_THINCLIENT_CONFIG_VARIABLE_GUID, readbuf, sizeof(XNOTE_THINCLIENT_CONFIG));
	if (Status == 0) {
		std::cout << ("Failed to set the variable : ") <<  GetLastError() << std::endl;
		return;
	}
	std::cout << ("The changes have been successfully applied.") << std::endl;
}