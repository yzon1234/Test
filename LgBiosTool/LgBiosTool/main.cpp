
#include "XnoteThinclientConfig.h"
#include "XnoteOpwConfig.h"
#include "Meta.h"
#include "DisplayBootOrder.h"

#define MAX_ITEMS 20
#define MAX_LENGTH 256
#define PROGRAM_VERSION      "TEST 1.0"
#define PROGRAM_BUILD_DATE   "251010"


char bootDescriptions[MAX_ITEMS][MAX_LENGTH];

void Useage(){
  std::cout << ("Useage : LgBiosTool [COMMAND]\n");
  std::cout << ("version                                      Show tool version                                      ") << std::endl;
  std::cout << ("help                                         Show tool usage                                        ") << std::endl;
  std::cout << ("print                                        Show Now Status                                        ") << std::endl;
  std::cout << ("enable            [Function]                 enable device                                          ") << std::endl;
  std::cout << ("disable           [Function]                 disable device                                         ") << std::endl;
  std::cout << ("                  WlanEnable                 Enable/Disable the wireless LAN (Wi-Fi)                ") << std::endl;
  std::cout << ("                  BluetoothEnable            Enable/Disable Blutetooth                              ") << std::endl;
  std::cout << ("                  MicroSdEnable              Enable/Disable MicroSd                                 ") << std::endl;
  std::cout << ("                  WebcamEnable               Enable/Disable Webcam                                  ") << std::endl;
  std::cout << ("                  UsbPortEnable              Enable/Disable all UsbPort                             ") << std::endl;
  std::cout << ("                  UsbPort[1-10]              Enable/Disable UsbPort[1-10]                           ") << std::endl;
  std::cout << ("                  UsbBootEnable              Enable/Disable UsbBoot                                 ") << std::endl;
  std::cout << ("                  PxeBoot                    Enable/Disable the network stack for PXE booting       ") << std::endl;
  std::cout << ("                  WolEnable                  Enables Wake-on-LAN functionality for remote wake-up   ") << std::endl;
  std::cout << ("                  LastPowerState             Saves the last power state of the system (on, off, last power state) for recovery. ") << std::endl;
  std::cout << ("bootorder         [USB HDD / Windows ...]    Change boot order                                      ") << std::endl;
  std::cout << ("admin / user      [password]                 Set Admin or user Password                             ") << std::endl;
  std::cout << ("pob               [TRUE / FALSE]             Set Password on Boot                                   ") << std::endl;
  std::cout << ("admin_status                                 Show Admin Password is set                             ") << std::endl;
  std::cout << ("user_status                                  Show User Password is set                              ") << std::endl;
  std::cout << ("save                                         Save the currently set configurations to the Bios_Config.txt ") << std::endl;
  std::cout << ("load                                         Load configuration from Bios_Config.txt and set        ") << std::endl;
}

std::wstring getBiosVendor()
{
	HKEY hKey;
	const wchar_t* subKey = L"HARDWARE\\DESCRIPTION\\System\\BIOS";
	const wchar_t* valueName = L"BIOSVendor";
	wchar_t value[256];
	DWORD value_length = sizeof(value);

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		if (RegQueryValueExW(hKey, valueName, nullptr, nullptr, (LPBYTE)value, &value_length) == ERROR_SUCCESS) {
			RegCloseKey(hKey);
			return std::wstring(value);
		}
		RegCloseKey(hKey);
	}

	return L"Unknown";
}

void printVersionString()
{
  std::cout << "Version: " << PROGRAM_VERSION << ", Build " << PROGRAM_BUILD_DATE << std::endl;
}

void printBootlist(){
	
	FILE *fp;
	char buffer[512];
    int count = 0;

	// Run the bcdedit command
	fp = _popen("bcdedit /enum firmware", "r");
	if (fp == NULL) {
		std::cout << ("Failed to run bcdedit.") << std::endl;
		return;
	}

	// Read and extract only the value part of "description"
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		char *desc = strstr(buffer, "description");
		if (desc != NULL && count < MAX_ITEMS) {
			// Move pointer to value part
			char *value = desc + strlen("description");
			while (*value == ' ' || *value == '\t') value++; // skip whitespace

			// Remove trailing newline
			size_t len = strlen(value);
			if (len > 0 && value[len - 1] == '\n') {
				value[len - 1] = '\0';
			}
            
			// Skip if value is "Setup" or "HiddenMenuSetup".. etc
			if (strcmp(value, "Setup") == 0){
				continue;
			}
			else if (strcmp(value, "HiddenMenuSetup") == 0){
				continue;
			}
			else if (strcmp(value, "SecureSetup") == 0){
				continue;
			}
			else if (strcmp(value, "Boot Menu") == 0){
				continue;
			}
			else if (strcmp(value, "Windows Recovery Environment") == 0){
				continue;
			}
			else if (strcmp(value, "F11 Recovery") == 0){
				continue;
			}
			else {
			  strncpy(bootDescriptions[count], value, MAX_LENGTH - 1);
			  bootDescriptions[count][MAX_LENGTH - 1] = '\0'; // null-terminate
			  count++;
			}
		}
	}

	_pclose(fp);

	// Print the list
	std::cout << ("Boot Descriptions:") << std::endl;
	for (int i = 0; i < count; i++) {
		std::cout << "  [" << i << "] " << bootDescriptions[i] << std::endl;
		}
	return;
	
}

void printBootlistforODM()
{
	DISPLAY_BOOTORDER* BootOrderList = NULL;

	//HANDLE hToken;
	DWORD pBufferSize;
	BYTE readbuf[sizeof(DISPLAY_BOOTORDER)] = { 0, };

	pBufferSize = GetFirmwareEnvironmentVariable(DISPLAY_BOOTORDER_CONFIG_VARIABLE_NAME, DISPLAY_BOOTORDER_CONFIG_VARIABLE_GUID, readbuf, sizeof(DISPLAY_BOOTORDER));
	if (pBufferSize == 0) {
		return;
	}

	BootOrderList = (DISPLAY_BOOTORDER*)readbuf;

	std::cout << ("Boot Descriptions:") << std::endl;
	
    for (int i = 0; i < MAX_BOOT_ENTRIES; ++i) {
		if(BootOrderList->BootDescriptions[i]!=NULL){
		  std::wcout << " [" << i << "] " << reinterpret_cast<wchar_t*>(BootOrderList->BootDescriptions[i]) << std::endl;
		}
    }

}
std::string get_current_executable_path() {
	char path[MAX_PATH];
	GetModuleFileNameA(NULL, path, MAX_PATH);
	return std::string(path);
}

std::string get_LgBiosPwTool_path() {

	char currentDir[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, currentDir);

	std::string toolPath = std::string(currentDir) + "\\LgBiosPwTool_signed.exe";
	return toolPath;

}

void restore_PE(std::vector<char> &binary_data, std::vector<unsigned char> signature) {
	
	// This is a task to restore the LgBiosTool binary before signing. 
	// Because it was hashed into binary before being signed.

	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(binary_data.data());
	if(dosHeader == NULL){return;}
	PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(binary_data.data() + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

	//size_t origin_NumberOfSections = ntHeaders->FileHeader.NumberOfSections;
	//size_t origin_SizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
		if (strncmp(reinterpret_cast<const char*>(sectionHeader->Name), ".signsec", IMAGE_SIZEOF_SHORT_NAME) == 0) {
			//std::cout << "find .signsec" << std::endl;
			memset(sectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
			--ntHeaders->FileHeader.NumberOfSections;
			ntHeaders->OptionalHeader.SizeOfImage -= signature.size();
	  }
	}
	memcpy(binary_data.data() + dosHeader->e_lfanew, ntHeaders, sizeof(PIMAGE_NT_HEADERS));

}
std::vector<unsigned char> read_signature_from_memory(HANDLE hModule)
{
	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
	if (dosHeader == NULL) { return{}; }
	PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);

	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, ++sectionHeader) {
		if (strncmp(reinterpret_cast<const char*>(sectionHeader->Name), ".signsec", IMAGE_SIZEOF_SHORT_NAME) == 0) {
			std::vector<unsigned char> signature(
				reinterpret_cast<BYTE*>(hModule) + sectionHeader->VirtualAddress,
				reinterpret_cast<BYTE*>(hModule) + sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize);
			return signature;
		}
	}
	//throw std::runtime_error(".signsec section not found.");
	return {};
}

#pragma pack(push, 1)
struct SMBIOSHeader {
	BYTE type;
	BYTE length;
	WORD handle;
};
#pragma pack(pop)

std::string GetStringFromTable(const BYTE* table, BYTE index) {
	if (index == 0) return "";
	const char* str = (const char*)(table);
	while (--index && *str) {
		str += strlen(str) + 1;
	}
	return std::string(str);
}

std::string GetSystemFamilyName() {
	DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
	if (size == 0) return "";

	std::vector<BYTE> buffer(size);
	if (GetSystemFirmwareTable('RSMB', 0, buffer.data(), size) != size) return "";

	const BYTE* p = buffer.data();
	const BYTE* end = p + size;

	while (p + sizeof(SMBIOSHeader) <= end) {
		const SMBIOSHeader* header = (const SMBIOSHeader*)p;

		if (header->type == 1) { // System Information
			const BYTE* strings = p + header->length;
			BYTE familyIndex = *(p + 0x1A); // offset 0x1A = Family string index
			return GetStringFromTable(strings, familyIndex);
		}

		const BYTE* strings = p + header->length;
		while (strings < end && (strings[0] != 0 || strings[1] != 0)) {
			strings++;
		}
		strings += 2; // double null
		p = strings;
	}
	return "";
}



int main(int argc, char* argv[]) {
      
	try {

		std::string familyName = GetSystemFamilyName();
		if (familyName.empty()) {
			std::cout << "Cannot read System Family Name!!!\n";
			return 1;
		}

		//std::cout << "System Family Name: " << familyName << "\n";

		if (familyName != "LG Cloud Device") {
			std::cout << ("This model does not support CLI Tool") << std::endl;
		}
		////////////////////////////////////////////////////////////////////////////////////
        //                           0.                                                   //
        ////////////////////////////////////////////////////////////////////////////////////

        if (IsDebuggerPresent()) {
            ExitProcess(0);
        }
        
		 BOOL debuggerPresent = FALSE;
		 CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
        
		 if (debuggerPresent) {
		 	ExitProcess(0);
		 }

        typedef NTSTATUS (WINAPI *NtSetInformationThreadFunc)(HANDLE, ULONG, PVOID, ULONG);
        NtSetInformationThreadFunc NtSetInformationThread = 
            (NtSetInformationThreadFunc)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
        if (NtSetInformationThread) {
            NtSetInformationThread(GetCurrentThread(), 0x11, NULL, 0); // ThreadHideFromDebugger
        }

		////////////////////////////////////////////////////////////////////////////////////
		//                           1. Read Signature from Memory                        //
		////////////////////////////////////////////////////////////////////////////////////
		HMODULE hModule = GetModuleHandle(NULL);
		if (hModule == NULL) {
			std::cout << "Fail to get hModule" << std::endl;
		}

		std::vector<unsigned char> signature = read_signature_from_memory(hModule);
#if DEBUG_BUILD
		for (size_t i = 0; i < signature.size(); i++) {
			printf("%02x ", static_cast<unsigned char>(signature[i]));
			if ((i + 1) % 16 == 0) {
				printf("\n");
			}
		}
		printf("\n");
#endif

		////////////////////////////////////////////////////////////////////////////////////
		//                           2. Read Binary LgBiosTool                            //
		////////////////////////////////////////////////////////////////////////////////////
		std::string exePath = get_current_executable_path();
		std::ifstream file(exePath, std::ios::binary);
		if (!file.is_open()) {
			throw std::runtime_error("Failed to open the executable file: " + exePath);
		}

		std::vector<char> binary_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
		file.close();

		////////////////////////////////////////////////////////////////////////////////////
		//                           3. Restore Original Binary                           //
		////////////////////////////////////////////////////////////////////////////////////
		size_t origin_data_size = binary_data.size() - signature.size();

		std::vector<char> origin_data(binary_data.begin(), binary_data.begin() + origin_data_size); // delete signkey in binary
		restore_PE(origin_data, signature);



		////////////////////////////////////////////////////////////////////////////////////
		//                            4. Verifty with public key                          //
		////////////////////////////////////////////////////////////////////////////////////

#if DEBUG_BUILD
		for (size_t i = 0; i < signature.size(); i++) {
			printf("%02x ", static_cast<char>(signature[i]));
			if ((i + 1) % 16 == 0) {
				printf("\n");
			}
		}
		printf("\n");
#endif

		if (!verify_with_public_key(origin_data, signature, public_key_pem)) {
			throw std::runtime_error("Verifiy Failed");
		}

		HANDLE hToken;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		{
			std::cout << "Fail to OpenProcessToken" << std::endl;
		}

		LUID luid;
		LookupPrivilegeValue(NULL, SE_SYSTEM_ENVIRONMENT_NAME, &luid);

		TOKEN_PRIVILEGES tkp;
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Luid = luid;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0) == 0)
		{
			std::cout << "Fail_To_AdjustTokenPrivileges" << std::endl;
		}

	    std::vector<char> origin_backup = origin_data;
#if BIOS_SECURITY_ON
        std::vector<unsigned char> hash = sha256(origin_data);
		WriteSecurityKey(hash, signature);
#endif

		if(!PrintThin(FALSE)) {return 1;}

		if (argc >=2 && _stricmp(argv[1], "print") == 0) {
			std::wstring biosVendor = getBiosVendor();
			std::wcout << L"BIOS Vendor:     " << biosVendor << std::endl;

            PrintThin(TRUE);
			if (biosVendor.find(L"Phoenix") != std::wstring::npos) {
				printBootlist();
			}
			else {
				printBootlistforODM();
			}
		}
        else if (argc >= 2 && _stricmp(argv[1], "version") == 0){
			printVersionString();
		}

		else if (argc >= 2 && _stricmp(argv[1], "save") == 0) {
		    SaveThin();
		} 

		else if (argc >= 2 && _stricmp(argv[1], "load") == 0) {
            LoadThin();		
		}

		else if (argc == 3 && _stricmp(argv[1], "enable") == 0) {
			WriteThin(argv[1] ,argv[2]);
		}

		else if (argc == 3 && _stricmp(argv[1], "disable") == 0) {
			WriteThin(argv[1] ,argv[2]);
		}

		else if (argc == 3 && _stricmp(argv[1], "bootorder") == 0) {
			WriteThin(argv[1] ,argv[2]);
		}

		else if (argc >= 2 && _stricmp(argv[1], "pob_status") == 0) {
			OpwReadPopStatus();
		}

		else if (argc >= 2 && _stricmp(argv[1], "pob") == 0) {
			OpwWritePopStatus(argv[2]);
		}

		else if (argc >= 2 && _stricmp(argv[1], "set") == 0) {
			OpwWritePassword2(argv[2]);
		}

		else if (argc >= 2 && (_stricmp(argv[1], "admin_status") == 0 || _stricmp(argv[1], "user_status") == 0)) {
			OpwCheckPasswordIsSet(argv[1]);
		}

		else if (argc >= 2 && _stricmp(argv[1], "help") == 0){
			Useage();
		}
		else{
			std::cout << "Please check useage." << std::endl;
			std::cout << "LgBiosTool_signed.exe help" << std::endl;
		}
	}
    

	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return 1;
	}
	return 0;
}