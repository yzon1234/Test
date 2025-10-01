#include "XnoteOpwConfig.h"
#include "Meta.h"
#define CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN 16

void OpwReadPopStatus() {
	XNOTE_OPW_STS_VARIABLE* XnoteOpwStatusVar = NULL;
	DWORD pBufferSize;
	BYTE readbuf[sizeof(XNOTE_OPW_STS_VARIABLE)] = { 0, };

	pBufferSize = GetFirmwareEnvironmentVariable(XNOTE_OPW_POB_VARIABLE_NAME, XNOTE_OPW_VARIABLE_GUID, readbuf, sizeof(XNOTE_OPW_STS_VARIABLE));
	if (pBufferSize == 0) {
		std::cout << ("Failed to get the variable : %d \n", GetLastError()) << std::endl;
		return;
	}

	XnoteOpwStatusVar = (XNOTE_OPW_STS_VARIABLE*)readbuf;
	std::cout << "PobSts : " << XnoteOpwStatusVar->PobSts << std::endl;
}

void OpwWritePopStatus(char *argv) {
	
	EFI_STATUS Status;
	DWORD pBufferSize;
	BYTE readbuf[sizeof(XNOTE_OPW_STS_VARIABLE)] = { 0, };

	XNOTE_OPW_STS_VARIABLE OpwStatsVar;
	pBufferSize = GetFirmwareEnvironmentVariable(XNOTE_OPW_POB_VARIABLE_NAME, XNOTE_OPW_VARIABLE_GUID, &OpwStatsVar, sizeof(XNOTE_OPW_STS_VARIABLE));
	if (pBufferSize == 0) {
		std::cout << ("Failed to get OpwStatsVar variable : %d \n", GetLastError()) << std::endl;

		std::cout << ("Make new OpwStatsVar \n");
		memset(&OpwStatsVar, 0x0, sizeof(XNOTE_OPW_STS_VARIABLE));
	}
  
	if(_stricmp(argv, "TRUE") == 0){
      OpwStatsVar.PobSts = 1;
	}
	else if(_stricmp(argv, "FALSE") == 0){
      OpwStatsVar.PobSts = 0;
	}
	else{
	  std::cout << ("Check Parameter True or false.") << std::endl;
	  return;
	}
	Status = SetFirmwareEnvironmentVariable(XNOTE_OPW_POB_VARIABLE_NAME, XNOTE_OPW_VARIABLE_GUID, &OpwStatsVar, sizeof(XNOTE_OPW_STS_VARIABLE));
	if (Status == 0) {
		std::cout << ("OpwWritePopStatus : Failed to set the variable : : ", GetLastError()) << std::endl;
	    return;
	}
	std::cout << ("PasswordOnBoot has been set successfully.") << std::endl;
   
}
void OpwCheckPasswordIsSet(char *argv1){

  XNOTE_OPW_STS_VARIABLE* XnoteOpwStatusVar = NULL;
  DWORD pBufferSize;
  BYTE readbuf[sizeof(XNOTE_OPW_STS_VARIABLE)] = { 0, };
  pBufferSize = GetFirmwareEnvironmentVariable(XNOTE_OPW_ISPWDSET_VARIABLE_NAME, XNOTE_OPW_VARIABLE_GUID, readbuf, sizeof(XNOTE_OPW_STS_VARIABLE));
  if (pBufferSize == 0) {
  	std::cout << ("Failed to get the variable : %d \n", GetLastError()) << std::endl;
  	return;
  }

  XnoteOpwStatusVar = (XNOTE_OPW_STS_VARIABLE*)readbuf;

  if (_stricmp(argv1, "admin_status") == 0 ){
	std::cout << ("AdminSts : ") << XnoteOpwStatusVar->AdminSts << std::endl;
  }
  else if (_stricmp(argv1, "user_status") == 0){
	std::cout << ("UserSts : ") << XnoteOpwStatusVar->UserSts << std::endl;
  }
 
}
/*
void OpwWritePassword(char *argv1,char *argv2){
	
	if(argv2 == NULL){
		std::cerr << "Please Enter Password" << std::endl;
		return;
	}
	std::cout << "OpwWritePassword\n" << std::endl;
	EFI_STATUS Status;
	UINT8 PasswordHash[CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN];
	std::cout << "Password : " << argv2 << std::endl;

    int wide_len = MultiByteToWideChar(CP_ACP, 0, argv2, -1, NULL, 0);
    if (wide_len <= 0) {
      std::cerr << "Failed to calculate wide char length" << std::endl;
      return;
    }

	CHAR16* argv_buf = (CHAR16*)malloc(wide_len * sizeof(CHAR16));
	if (!argv_buf) {
	  std::cerr << "Memory allocation failed" << std::endl;
	  return;
	}
    
    int result = MultiByteToWideChar(CP_ACP, 0, argv2, -1, (LPWSTR)argv_buf, wide_len);
    if (result == 0) {
      std::cerr << "MultiByteToWideChar failed" << std::endl;
      free(argv_buf);
      return;
    }
    unsigned int hash_length = 0;
	if(!EncodePassword(argv_buf, wcslen((const wchar_t*)argv_buf), PasswordHash, &hash_length)){
      return;
	}

#if DEBUG_BUILD
	for (size_t i = 0; i < CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN; i++) {
		printf("%02x ", PasswordHash[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n");
#endif
    char User_Name[20];
	if( _stricmp(argv1, "admin") == 0 ){
      strcpy(User_Name, XNOTE_OPW_VARIABLE_NAME);
	}
	else if ( _stricmp(argv1, "user") == 0 ){
	  strcpy(User_Name, XNOTE_OPW_USER_VARIABLE_NAME);
	}
	else{
	  Useage();
	}


	Status = SetFirmwareEnvironmentVariable(User_Name, XNOTE_OPW_VARIABLE_GUID, PasswordHash, sizeof(PasswordHash));
	if (Status == 0) {
		std::cout << ("Failed to set the password : ") << GetLastError() << std::endl;
		return;
	}
	std::cout << ("Password has been set successfully.") << std::endl;

	return;
}
*/
void OpwWritePassword2(char *argv2){
	UINT8 FilePasswordHash[CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN];
	std::vector<unsigned char> signature(256);
    EFI_STATUS Status;
	 char User_Name[20];
	 std::string filename;

	if( _stricmp(argv2, "admin") == 0 ){
        filename = "admin.sign";
		strcpy_s(User_Name, sizeof(User_Name), XNOTE_OPW_VARIABLE_NAME);
	}
	else if ( _stricmp(argv2, "user") == 0 ){
	    filename = "user.sign";
		strcpy_s(User_Name, sizeof(User_Name), XNOTE_OPW_USER_VARIABLE_NAME);
	}
	else{
		std::cout << "Please check useage." << std::endl;
		return;
	}

	std::ifstream inFile(filename, std::ios::binary);
	if (!inFile) {
		std::cerr << "Cannot open " << filename << " file.\n";
	}

	inFile.read(reinterpret_cast<char*>(FilePasswordHash), CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN);
	if (_stricmp(argv2, "admin") == 0) {
		inFile.read(reinterpret_cast<char*>(signature.data()), signature.size());

		////////////////////////////////////////////////////////////////////////////////////
		//                           2. Read Binary LgBiosTool                            //
		////////////////////////////////////////////////////////////////////////////////////
		std::string exePath = get_LgBiosPwTool_path();
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
	}
	

	if (!inFile) {
		std::cerr << "Cannot read " << filename << " file.\n";
	}
	inFile.close();

#if DEBUG_BUILD
	for (size_t i = 0; i < CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN; i++) {
		printf("%02x ", FilePasswordHash[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n");
#endif

	Status = SetFirmwareEnvironmentVariable(User_Name, XNOTE_OPW_VARIABLE_GUID, FilePasswordHash, sizeof(FilePasswordHash));
	if (Status == 0) {
		std::cout << ("Failed to set the password : ") << GetLastError() << std::endl;
		return;
	}
	std::cout << ("Password has been set successfully.") << std::endl;

	return;
}