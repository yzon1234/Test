#include "Meta.h"
#include "XnoteOpwConfig.h"

CHAR16 *MultiByteToWideCharFunc(const char* password){
int wide_len = MultiByteToWideChar(CP_ACP, 0, password, -1, NULL, 0);
	if (wide_len <= 0) {
		std::cerr << "Failed to calculate wide char length" << std::endl;
		return nullptr;
	}

	CHAR16* argv_buf = (CHAR16*)malloc(wide_len * sizeof(CHAR16));
	if (!argv_buf) {
		std::cerr << "Memory allocation failed" << std::endl;
		return nullptr;
	}

	int result = MultiByteToWideChar(CP_ACP, 0, password, -1, (LPWSTR)argv_buf, wide_len);
	if (result == 0) {
		std::cerr << "MultiByteToWideChar failed" << std::endl;
		free(argv_buf);
		return nullptr;
	}
  return argv_buf;
}

void genPassword(const char* oldpassword, const char* newpassword, char* argv2, std::vector<unsigned char> signature) {
	constexpr size_t MAX_PASSWORD_LENGTH = 12;
	UINT8 OldPasswordHash[CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN];
	UINT8 NewPasswordHash[CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN];

	std::string filename;
	if (_stricmp(argv2, "admin") == 0) {
		filename = "admin.sign";
	}
	else if (_stricmp(argv2, "user") == 0) {
		filename = "user.sign";
	}
	else {
		std::cerr << "Invalid user type.\n";
		return;
	}

	if (oldpassword == nullptr || strlen(oldpassword) == 0 ||
		newpassword == nullptr || strlen(newpassword) == 0) {
		std::cerr << "Please enter both old and new passwords." << std::endl;
		return;
	}

	if (strlen(newpassword) > MAX_PASSWORD_LENGTH) {
		std::cerr << "New password must be 12 characters or less." << std::endl;
		return;
	}

	//  2.Cal Old Passwrod Hash
    CHAR16* argv_buf = MultiByteToWideCharFunc(oldpassword);
	
	unsigned int hash_length = 0;
	
	if(!EncodePassword(argv_buf, wcslen((const wchar_t*)argv_buf), OldPasswordHash, &hash_length)){
	  free(argv_buf);
      return;
	}
    free(argv_buf);

#if DEBUG_BUILD
	for (size_t i = 0; i < CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN; i++) {
		printf("%02x ", OldPasswordHash[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	
#endif

	if (!checkOpwReadHash(OldPasswordHash)) {
      std::cout << "Password is Wrong!!" << std::endl;
	  std::cout << "Please enter admin password !" << std::endl;
	  return ;
	}

	if (newpassword == NULL || oldpassword == NULL) {
		std::cerr << "Please Enter Password" << std::endl;
	}

	CHAR16* argv_buf2 = MultiByteToWideCharFunc(oldpassword);
	hash_length = 0;
	if(!EncodePassword(argv_buf2, wcslen((const wchar_t*)argv_buf2), NewPasswordHash, &hash_length)){
	  free(argv_buf2);
      return;
	}

	free(argv_buf2);
	std::ofstream outFile(filename, std::ios::binary);
	if (!outFile) {
		std::cerr << "Failed to open file for writing. It will be created.\n";
	}

	outFile.write(reinterpret_cast<char*>(NewPasswordHash), CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN);

	if (_stricmp(argv2, "admin") == 0) {
		// Write signature vector
		if (!signature.empty()) {
			outFile.write(reinterpret_cast<const char*>(signature.data()), signature.size());
		}
	}
	outFile.close();

	std::cout << "Successfully generated " << filename << " file. " << std::endl;
	
	return;
}

void genPassword(const char* newpassword, char* argv2, std::vector<unsigned char> signature) {
	constexpr size_t MAX_PASSWORD_LENGTH = 12;
	UINT8 PasswordHash[CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN];
	std::string filename;

	if (_stricmp(argv2, "admin") == 0) {
		filename = "admin.sign";
	}
	else if (_stricmp(argv2, "user") == 0) {
		filename = "user.sign";
	}
	else {
		std::cerr << "Invalid user type.\n";
		return;
	}

	if (newpassword == nullptr || strlen(newpassword) == 0) {
		std::cerr << "Please enter a non-empty password." << std::endl;
		return;
	}

	if (strlen(newpassword) > MAX_PASSWORD_LENGTH) {
		std::cerr << "Password must be 12 characters or less." << std::endl;
		return;
	}

	CHAR16* argv_buf = MultiByteToWideCharFunc(newpassword);
	if (!argv_buf) {
		std::cerr << "Failed to convert password to wide char." << std::endl;
		return;
	}

	unsigned int hash_length = 0;
	if (!EncodePassword(argv_buf, wcslen((const wchar_t*)argv_buf), PasswordHash, &hash_length)) {
		free(argv_buf);
		std::cerr << "Password encoding failed." << std::endl;
		return;
	}
	free(argv_buf);

	std::ofstream outFile(filename, std::ios::binary);
	if (!outFile) {
		std::cerr << "Failed to open file for writing. It will be created.\n";
	}

	outFile.write(reinterpret_cast<char*>(PasswordHash), CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN);

	if (_stricmp(argv2, "admin") == 0) {
		if (!signature.empty()) {
			outFile.write(reinterpret_cast<const char*>(signature.data()), signature.size());
		}
		else {
			std::cout << "Signature is empty!!!.\n";
			outFile.close();
			return;
		}
	}

	outFile.close();
	std::cout << "Successfully generated " << filename << " file." << std::endl;
}