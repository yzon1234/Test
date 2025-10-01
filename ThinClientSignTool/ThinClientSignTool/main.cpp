#include "openssl.h"
#include <windows.h>
#include <direct.h>

const std::string private_key_path = "ThinSignTool\\JMKTEST.pem";

#define SIGNSEC_SIZE 0x200

void AddSectionToPE(std::vector<unsigned char> Signature, std::vector<char> binary_data, const std::string& binary_path) {

	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(binary_data.data());
	PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(binary_data.data() + dosHeader->e_lfanew);
	std::cout << ntHeaders->FileHeader.NumberOfSections << std::endl;
	PIMAGE_SECTION_HEADER lastsectionHeader = IMAGE_FIRST_SECTION(ntHeaders) + ntHeaders->FileHeader.NumberOfSections - 1;
	PIMAGE_SECTION_HEADER sectionHeader     = IMAGE_FIRST_SECTION(ntHeaders) + ntHeaders->FileHeader.NumberOfSections; // Addressfor First Section +7
	strncpy(reinterpret_cast<char*>(sectionHeader->Name), ".signsec", IMAGE_SIZEOF_SHORT_NAME);

	sectionHeader->Misc.VirtualSize = Signature.size(); //256byte
	sectionHeader->VirtualAddress = ( ntHeaders->OptionalHeader.SizeOfImage + 0xFFF ) & ~0xFFF; // 4KB Align (RVA)
	sectionHeader->SizeOfRawData = Signature.size(); //256byte
	sectionHeader->PointerToRawData = lastsectionHeader->PointerToRawData + lastsectionHeader->SizeOfRawData;
	sectionHeader->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

	ntHeaders->FileHeader.NumberOfSections++;
	ntHeaders->OptionalHeader.SizeOfImage += sectionHeader->Misc.VirtualSize;

	// Generate Signed_binary_data
	std::vector<char> Signed_binary_data(binary_data);
	Signed_binary_data.resize(binary_data.size() + sectionHeader->SizeOfRawData);

	size_t ntHeaderoffset = reinterpret_cast<size_t>(ntHeaders) - reinterpret_cast<size_t>(binary_data.data());
	std::cout << ntHeaderoffset << std::endl;
	std::memcpy(Signed_binary_data.data() + ntHeaderoffset, ntHeaders, sizeof(IMAGE_NT_HEADERS));
	
	std::copy(Signature.begin(), Signature.end(), Signed_binary_data.begin() + sectionHeader->PointerToRawData);
    
	 char curDir[100];
	_getcwd(curDir, 100);

	std::cout << curDir << std::endl;
	std::string new_binary_path = curDir;
	std::ofstream file(new_binary_path + "\\LgBiosTool_signed.exe", std::ios::binary);
	if (!file.is_open()) {
		std::cerr << "Unable to open file: " << new_binary_path << std::endl;
		return;
	}
	file.write(Signed_binary_data.data(), Signed_binary_data.size());
	file.close();
}

std::string getExecutablePath() {
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string exePath(buffer);
	return exePath.substr(0, exePath.find_last_of("\\/")); // 폴더 경로만 추출
}


int main(int argc, char* argv[])
{
	const char* opensslVersion = displayOpenSSLVersion();
	std::cout << opensslVersion << std::endl;
	


	std::string exeDir = getExecutablePath();
	std::string private_key_path = exeDir + "\\ThinClient_PrivateKey.pem";

	if (argc < 2) {
		std::cout << "HELP" << std::endl;
		return 0;
	}

	////////////////////////////////////////////////////////////////////////////////////
	//                              1. Read file to sign                              //
	////////////////////////////////////////////////////////////////////////////////////

	const std::string binary_path = argv[1];
	std::ifstream before_Sign(binary_path, std::ios::binary);
	if (!before_Sign) {
		std::cout << "Failed to open the file." << std::endl;
		return 1;
	}

	std::vector<char> before_Data((std::istreambuf_iterator<char>(before_Sign)), std::istreambuf_iterator<char>());
	before_Sign.close();

	/*
	for (size_t i = 0; i < before_Data.size(); i++) {
		printf("%02x ", static_cast<unsigned char>(before_Data[i]));
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n");
	*/

	////////////////////////////////////////////////////////////////////////////////////
	//                            2. Generate Signing Key                             //
	////////////////////////////////////////////////////////////////////////////////////

	const std::vector<unsigned char> SignKey = generate_SignKey(before_Data, private_key_path, binary_path);

	////////////////////////////////////////////////////////////////////////////////////
	//                       3. Make PE Section & Add Sign to PE                      //
	////////////////////////////////////////////////////////////////////////////////////

	AddSectionToPE(SignKey, before_Data, binary_path);

	return 0;
}