#include "kmHook.h"

Deploy_Custom_JMP_Pool(GET_OUT, "win32kfull.sys", "NtUserResolveDesktopForWOW");

NTSTATUS DriverEntry() {



	return STATUS_SUCCESS;
}

