#include <stdio.h>
#include <conio.h>
#include <iostream>
#include "Meta.h"
#include "XnoteOpwConfig.h"

int main(int argc, char* argv[]) 
{

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
		//Useage();
	}
	else if (argc >= 2 && _stricmp(argv[1], "gen") == 0) {
		if (_stricmp(argv[2], "admin") == 0) {
			if (argc == 4) { // newpassword
				if (!OpwCheckPasswordIsSet(argv[2])) {
					genAdminPassword(argv[3]);
				}
			}
			else if (argc == 5) { // oladpassword, newpassword
				genAdminPassword(argv[3], argv[4]);
			}
		}
		else if (_stricmp(argv[2], "user") == 0) {

		}
		else {
			return 1;
		}
	}
	return 0;
}