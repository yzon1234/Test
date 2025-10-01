#include "XnoteOpwConfig.h"
#include "Meta.h"

#define CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN 16


bool checkOpwReadHash(UINT8 * OldPasswordHash) {

	XNOTE_OPW_VARIABLE* opwvariable = NULL;
	DWORD pBufferSize;
	BYTE readbuf[sizeof(XNOTE_OPW_VARIABLE)] = { 0, };
	pBufferSize = GetFirmwareEnvironmentVariable(XNOTE_OPW_BACKUP_VARIABLE_NAME, XNOTE_OPW_VARIABLE_GUID, readbuf, sizeof(XNOTE_OPW_VARIABLE));
	if (pBufferSize == 0) {
		std::cout << ("Failed to get the variable : ") << GetLastError() << std::endl;
		return FALSE;
	}

	opwvariable = (XNOTE_OPW_VARIABLE*)readbuf;

	for (size_t i = 0; i < CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN; i++) {
		std::cout << std::hex << std::setw(2) << std::setfill('0')
			<< static_cast<int>(readbuf[i]) << " ";
		if ((i + 1) % 16 == 0) {
			std::cout << std::endl;
		}
	}

	if (memcmp(OldPasswordHash, opwvariable->buffer, CONFIG_SYSTEM_CREDENTIAL_PASSWORD_HASH_LEN) == 0) {
		return TRUE;
	}
	return FALSE;

	
    
//	XNOTE_OPW_VARIABLE* XnoteOpwStatusVar = NULL;
//	DWORD pBufferSize;
//	BYTE readbuf[sizeof(XNOTE_OPW_STS_VARIABLE)] = { 0, };
//
//	pBufferSize = GetFirmwareEnvironmentVariable(XNOTE_OPW_POB_VARIABLE_NAME, XNOTE_OPW_VARIABLE_GUID, readbuf, sizeof(XNOTE_OPW_STS_VARIABLE));
//	if (pBufferSize == 0) {
//		std::cout << ("Failed to get the variable : %d \n", GetLastError()) << std::endl;
//		return;
//	}
//
//	XnoteOpwStatusVar = (XNOTE_OPW_STS_VARIABLE*)readbuf;
//	printf("PobSts : %d\n", XnoteOpwStatusVar->PobSts);
}

bool OpwCheckPasswordIsSet(char* argv1) {

	XNOTE_OPW_STS_VARIABLE* XnoteOpwStatusVar = NULL;
	DWORD pBufferSize;
	BYTE readbuf[sizeof(XNOTE_OPW_STS_VARIABLE)] = { 0, };
	pBufferSize = GetFirmwareEnvironmentVariable(XNOTE_OPW_ISPWDSET_VARIABLE_NAME, XNOTE_OPW_VARIABLE_GUID, readbuf, sizeof(XNOTE_OPW_STS_VARIABLE));
	if (pBufferSize == 0) {
		std::cout << ("Failed to get the variable : %d \n", GetLastError()) << std::endl;
		throw std::runtime_error("Failed to get the variable\n");
	}

	XnoteOpwStatusVar = (XNOTE_OPW_STS_VARIABLE*)readbuf;

	if (_stricmp(argv1, "admin") == 0) {
		if (XnoteOpwStatusVar->AdminSts == 0) {
			return FALSE;
		}
		else if (XnoteOpwStatusVar->AdminSts == 1){
			std::cout << "A password has been set. Please enter your previous password." << std::endl;
			return TRUE;
		}
	}
	else if (_stricmp(argv1, "user") == 0) {
		if (XnoteOpwStatusVar->UserSts == 0) {
			return FALSE;
		}
		else if (XnoteOpwStatusVar->UserSts == 1) {
			return TRUE;
		}
	}

}
