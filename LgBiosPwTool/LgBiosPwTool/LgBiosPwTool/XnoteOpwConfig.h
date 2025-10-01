#include "Meta.h"
#include "openssl.h"

// {EC6F03A4-68EA-4185-9151-CF8070C7658A}
#define XNOTE_OPW_VARIABLE_GUID "{EC6F03A4-68EA-4185-9151-CF8070C7658A}"


#define XNOTE_OPW_BACKUP_VARIABLE_NAME    "XnoteOpwBackupVar"
#define XNOTE_OPW_USER_VARIABLE_NAME      "XnoteOpwUserVar"
#define XNOTE_OPW_ISPWDSET_VARIABLE_NAME  "XnoteOpwIsSet" 
#define XNOTE_OPW_POB_VARIABLE_NAME       "XnoteOpwPob"
#define XNOTE_OPW_VARIABLE_GUID "{EC6F03A4-68EA-4185-9151-CF8070C7658A}"


typedef struct _XNOTE_OPW_VAR {
	CHAR8 buffer[16];
} XNOTE_OPW_VARIABLE;

//LGEMOD:BEGIN [BSK220707A] - [ETC][Thin][PCSWBIOS-141] Support User password Set/Clear and retrieve Status
typedef struct _XNOTE_OPW_STS_VARIABLE {
	CHAR8 AdminSts;
	CHAR8 UserSts;
	CHAR8 PobSts;
	CHAR8 PobBackSts;
} XNOTE_OPW_STS_VARIABLE;
//LGEMOD:END [BSK220707A]

void OpwReadPopStatus();
void OpwWritePopStatus(char* argv);
void OpwWritePassword(char* argv1, char* argv2);
bool OpwCheckPasswordIsSet(char* argv1);
bool checkOpwReadHash(UINT8* password);