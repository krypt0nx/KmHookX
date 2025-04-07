// simple tool to change the

#include "kmHook.h"


typedef NTSTATUS(*bgpClearScreenR)(ULONG color);

bgpClearScreenR bgpClearScreen;

NTSTATUS keBugCheckHooked(ULONG color)

{
	kDbg("Wtf!! A bugcheck????????????????????????????????????????????????????");


	return bgpClearScreen(0x8A72BB);


}

NTSTATUS DriverEntry() {

	PVOID keb = (PVOID)((LONG_PTR)KeBugCheckEx + 0x001af048); // may vary on different versions and may not work for your version.
	//if you want to get the offset then enter in windbg: ? nt!BgpClearScreen - nt!KeBugCheckEx


	kDbgStatus("The BgpClearScreen: 0x%p\n", keb);


	kmHookFunction(keb, keBugCheckHooked, &(PVOID&)KeBugCheck2);

	KeBugCheck(CRITICAL_PROCESS_DIED);

	return STATUS_SUCCESS;
}

