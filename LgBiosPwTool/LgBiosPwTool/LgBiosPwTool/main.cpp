#include <stdio.h>
#include <conio.h>
#include <iostream>
#include "Meta.h"
#include "XnoteOpwConfig.h"

#define PROGRAM_VERSION      "TEST 1.0"
#define PROGRAM_BUILD_DATE   "251010"

void printVersionString()
{
	std::cout << "Version: " << PROGRAM_VERSION << ", Build " << PROGRAM_BUILD_DATE << std::endl;

}
void useage()
{
	std::cout << "useage : LgBiosPwTool [COMMAND]\n";
	std::cout << "gen [admin/user] NewPassword\n";
	std::cout << "gen [admin] OldPassword NewPassword\n";
}

std::string get_current_executable_path() {
	char path[MAX_PATH];
	GetModuleFileNameA(NULL, path, MAX_PATH);
	return std::string(path);
}

void restore_PE(std::vector<char>& binary_data, std::vector<unsigned char> signature) {

	// This is a task to restore the LgBiosTool binary before signing. 
	// Because it was hashed into binary before being signed.

	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(binary_data.data());
	if (dosHeader == NULL) { return; }
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
int main(int argc, char* argv[]) 
{

	try {

		if (IsDebuggerPresent()) {
			ExitProcess(0);
		}

		BOOL debuggerPresent = FALSE;
		CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);

		if (debuggerPresent) {
			ExitProcess(0);
		}

		typedef NTSTATUS(WINAPI* NtSetInformationThreadFunc)(HANDLE, ULONG, PVOID, ULONG);
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

		if (argc >= 2 && _stricmp(argv[1], "help") == 0) {
			useage();
		}
		else if (argc >= 2 && _stricmp(argv[1], "gen") == 0) {
			if (_stricmp(argv[2], "admin") == 0) {
				if (argc == 4) { // newpassword
					if (!OpwCheckPasswordIsSet(argv[2])) {
						genPassword(argv[3], argv[2], signature);
					}
				}
				else if (argc == 5) { // oladpassword, newpassword
					genPassword(argv[3], argv[4], argv[2], signature);
				}
			}
			else if (_stricmp(argv[2], "user") == 0) {
				if (argc == 4) { // newpassword
					if (!OpwCheckPasswordIsSet(argv[2])) {
						genPassword(argv[3], argv[2], signature);
					}
				}
				else {
					useage();
					return 1;
				}
			}
			else {
				useage();
				return 1;
			}
		}

		else if (argc >= 2 && _stricmp(argv[1], "version") == 0) {
			printVersionString();
		}

		else {
			useage();
		}
	}

	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return 1;
	}
	return 0;
}