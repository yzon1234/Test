#include "Meta.h"
#include "openssl.h"

// {EC6F03A4-68EA-4185-9151-CF8070C7658A}
#define XNOTE_OPW_VARIABLE_GUID "{EC6F03A4-68EA-4185-9151-CF8070C7658A}"


#define XNOTE_OPW_BACKUP_VARIABLE_NAME    "XnoteOpwBackupVar"
#define XNOTE_OPW_USER_VARIABLE_NAME      "XnoteOpwUserVar"
#define XNOTE_OPW_ISPWDSET_VARIABLE_NAME  "XnoteOpwIsSet" 


typedef struct _XNOTE_OPW_VAR {
	CHAR8 buffer[16];
} XNOTE_OPW_VARIABLE;

typedef struct _XNOTE_OPW_STS_VARIABLE {
	CHAR8 AdminSts;
	CHAR8 UserSts;
	CHAR8 PobSts;
	CHAR8 PobBackSts;
} XNOTE_OPW_STS_VARIABLE;

bool OpwCheckPasswordIsSet(char* argv1);
bool checkOpwReadHash(UINT8* password);