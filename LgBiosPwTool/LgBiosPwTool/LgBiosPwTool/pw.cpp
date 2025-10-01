#include "Meta.h"
#include "XnoteOpwConfig.h"

void genAdminPassword(char* oldpassword, char* newpassword) {
	UINT8 OldPasswordHash[CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN];
	UINT8 NewPasswordHash[CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN];
	UINT8 FilePasswordHash[CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN];
	EFI_STATUS Status;
	//  2.Cal Old Passwrod Hash

	int wide_len = MultiByteToWideChar(CP_ACP, 0, oldpassword, -1, NULL, 0);
	if (wide_len <= 0) {
		std::cerr << "Failed to calculate wide char length" << std::endl;
	}

	CHAR16* argv_buf = (CHAR16*)malloc(wide_len * sizeof(CHAR16));
	if (!argv_buf) {
		std::cerr << "Memory allocation failed" << std::endl;
	}

	int result = MultiByteToWideChar(CP_ACP, 0, oldpassword, -1, (LPWSTR)argv_buf, wide_len);
	if (result == 0) {
		std::cerr << "MultiByteToWideChar failed" << std::endl;
		free(argv_buf);
	}
	unsigned int hash_length = 0;
	Status = EncodePassword(argv_buf, wcslen((const wchar_t*)argv_buf), OldPasswordHash, &hash_length);

	printf("Old Password\n");
	for (size_t i = 0; i < CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN; i++) {
		printf("%02x ", OldPasswordHash[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	
	if (!checkOpwReadHash(OldPasswordHash)) {
      std::cout << "Password is Wrong!!" << std::endl;
	  return ;
	}


	if (newpassword == NULL || oldpassword == NULL) {
		std::cerr << "Please Enter Password" << std::endl;
	}
	std::cout << "Old Password : " << oldpassword << std::endl;
	std::cout << "New Password : " << newpassword << std::endl;

//  1.Read Old Password hash
	//std::ifstream inFile("admin.sign", std::ios::binary);
	//if (!inFile) {
	//	std::cerr << "Cannot open admin.sign file.\n";
	//}

	//inFile.read(reinterpret_cast<char*>(FilePasswordHash), CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN);
	//if (!inFile) {
	//	std::cerr << "Cannot read amin.sign file.\n";
	//}
	//inFile.close();


	wide_len = MultiByteToWideChar(CP_ACP, 0, newpassword, -1, NULL, 0);
	if (wide_len <= 0) {
		std::cerr << "Failed to calculate wide char length" << std::endl;
	}

	CHAR16* argv_buf2 = (CHAR16*)malloc(wide_len * sizeof(CHAR16));
	if (!argv_buf2) {
		std::cerr << "Memory allocation failed" << std::endl;
	}

	result = MultiByteToWideChar(CP_ACP, 0, newpassword, -1, (LPWSTR)argv_buf2, wide_len);
	if (result == 0) {
		std::cerr << "MultiByteToWideChar failed" << std::endl;
		free(argv_buf2);
	}
	hash_length = 0;
	Status = EncodePassword(argv_buf2, wcslen((const wchar_t*)argv_buf2), NewPasswordHash, &hash_length);
	std::ofstream outFile("admin.sign", std::ios::binary);
	if (!outFile) {
		std::cerr << "The file does not exist so it will be created.\n";
	}


	outFile.write(reinterpret_cast<char*>(NewPasswordHash), CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN);
	outFile.close();

	std::cout << "Successfully generated admin.sign file.\n";
	
	return;

}

void genAdminPassword(char* newpassword) {
	UINT8 PasswordHash[CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN];
	EFI_STATUS Status;

	if (newpassword == NULL) {
		std::cerr << "Please Enter Password" << std::endl;
		return;
	}

	std::cout << "Password : " << newpassword << std::endl;

	int wide_len = MultiByteToWideChar(CP_ACP, 0, newpassword, -1, NULL, 0);
	if (wide_len <= 0) {
		std::cerr << "Failed to calculate wide char length" << std::endl;
	}

	CHAR16* argv_buf = (CHAR16*)malloc(wide_len * sizeof(CHAR16));
	if (!argv_buf) {
		std::cerr << "Memory allocation failed" << std::endl;
	}

	int result = MultiByteToWideChar(CP_ACP, 0, newpassword, -1, (LPWSTR)argv_buf, wide_len);
	if (result == 0) {
		std::cerr << "MultiByteToWideChar failed" << std::endl;
		free(argv_buf);
	}
	unsigned int hash_length = 0;
	Status = EncodePassword(argv_buf, wcslen((const wchar_t*)argv_buf), PasswordHash, &hash_length);

	for (size_t i = 0; i < CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN; i++) {
		printf("%02x ", PasswordHash[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n");
	std::ofstream outFile("admin.sign", std::ios::binary);
	if (!outFile) {
		std::cerr << "The file does not exist so it will be created.\n";
	}


	outFile.write(reinterpret_cast<char*>(PasswordHash), CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN);
	outFile.close();

	std::cout << "Successfully generated admin.sign file.\n";
	return;
}

