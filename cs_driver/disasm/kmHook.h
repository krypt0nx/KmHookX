#pragma once

#include "JMPFixer.h"

PVOID GetFunctionExport(PVOID base, const char* func) {
	PIMAGE_DOS_HEADER dosh = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS ntheaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)base + dosh->e_lfanew);
	PIMAGE_OPTIONAL_HEADER optional = &ntheaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY exports = &optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	PIMAGE_EXPORT_DIRECTORY dir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)base + exports->VirtualAddress);

	ULONG* aon = (ULONG*)((ULONG_PTR)base + dir->AddressOfNames);
	USHORT* aono = (USHORT*)((ULONG_PTR)base + dir->AddressOfNameOrdinals);
	ULONG* aof = (ULONG*)((ULONG_PTR)base + dir->AddressOfFunctions);

	for (int i = 0; i < dir->NumberOfNames; ++i) {
		char* name = (char*)((ULONG_PTR)base + aon[i]);
		USHORT ordinal = aono[i];
		PVOID function = (PVOID)((ULONG_PTR)base + aof[ordinal]);


		if (_stricmp(func, name) == 0) {
			kDbgStatus("function name: %s\n", name);
			kDbgStatus("function address: 0x%p\n", function);
			return function;
		}


	}
	return nullptr;
}

PVOID FindModule(const char* modula) {
	ULONG size;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &size);

	if (status != STATUS_INFO_LENGTH_MISMATCH)
		return (PVOID)status;

	PRTL_PROCESS_MODULES poolAlloc = reinterpret_cast<PRTL_PROCESS_MODULES>(ExAllocatePool(NonPagedPool, size));
	if (!poolAlloc)
		return (PVOID)0x193811120;


	status = ZwQuerySystemInformation(SystemModuleInformation, poolAlloc, size, NULL);

	if (!NT_SUCCESS(status))
		return (PVOID)status;

	PVOID Addr = nullptr;

	for (ULONG i = 0; i < poolAlloc->NumberOfModules; i++) {
		RTL_PROCESS_MODULE_INFORMATION mod = poolAlloc->Modules[i];

		kDbgStatus("Name; %s\n", mod.FullPathName);

		if (strstr(mod.FullPathName, modula)) {
			Addr = mod.ImageBase;
			break;
		}
	}

	ExFreePool(poolAlloc);

	return Addr;
}

void CraftJMP(PVOID addr, BYTE* dest) {
	BYTE Bt[] = {
		0x48, 0xB8, 0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00,         // mov rax, 0x0000000000000
		0xFF, 0xE0															// jmp rax

	};
	*((PULONG64)((PUCHAR)Bt + 2)) = reinterpret_cast<ULONG64>(addr);
	memcpy(dest, Bt, sizeof(Bt));

}
_IRQL_requires_max_(DISPATCH_LEVEL)
void WriteToReadOnly(PVOID address, BYTE* writewhat, SIZE_T size) {
	PMDL mdl = IoAllocateMdl(address, size, NULL, NULL, NULL);

	if (!mdl) {
		kDbg("Failed to allocate MDL.\n");
		return;
	}

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

	PVOID mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, address, FALSE, NormalPagePriority);

	if (!mapping) {
		kDbg("Failed to create mapping for mdl.\n");
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return;
	}

	if (!NT_SUCCESS(MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE))) {
		kDbg("Failed to apply protection for MDL.\n");
		MmUnmapLockedPages(mapping, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return;
	}


	memcpy(mapping, writewhat, size);

	MmUnmapLockedPages(mapping, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
}
PVOID kmCreateJMP(PVOID target) {

	static ULONG_PTR jmpIndex = 0;

	PVOID base = FindModule("ntoskrnl.exe");

	PVOID TargetFunction = GetFunctionExport(base, "CarCopyRuleViolationDetails");

	SIZE_T size = JMPFixer::GetFunctionSize(TargetFunction);

	if (size <= 12 * jmpIndex) {
		kDbgError("WARNING: Appropriate size reached. Please find a new untriggered function! (size = %d) \n", 12 * jmpIndex);
		return (PVOID)0xCCCCCC111;
	}
	
	if (!base) {
		kDbg("Failed to find the base address of ntoskrnl.exe\n");
		return nullptr;
	}
	if (!TargetFunction) {
		kDbg("Failed to find the target function in ntoskrnl.exe\n");
		return nullptr;
	}

	BYTE jmp[12];

	CraftJMP(target, jmp);

	PVOID realTF = (PVOID)((ULONG_PTR)TargetFunction + (sizeof(jmp) * jmpIndex));

	WriteToReadOnly(realTF, jmp, sizeof(jmp));

	jmpIndex += 1;

	kDbgStatus("Final address 0x%p\n",realTF);

	return realTF;
}
#define Deploy_Custom_JMP_PoolEx(modname,moduleName,base,address) \
	PVOID modname(PVOID target) {\
    static ULONG_PTR jmpIndex = 0; \
    PVOID base = FindModule(moduleName); \
    PVOID TargetFunction = address; \
	SIZE_T size = JMPFixer::GetFunctionSize(TargetFunction); \
	if (size <= 12 * jmpIndex) { \
		kDbgError("WARNING: Appropriate size reached. Please find a new untriggered function! (size = %d) \n", 12 * jmpIndex); \
		return (PVOID)0xCCCCCC111; \
	} \
    if (!base) { \
        kDbg("Failed to find the base address of ntoskrnl.exe\n"); \
        return nullptr; \
    } \
    if (!TargetFunction) { \
        kDbg("Failed to find the target function in ntoskrnl.exe\n"); \
        return nullptr; \
    } \
    BYTE jmp[12]; \
    CraftJMP(target, jmp); \
    PVOID realTF = (PVOID)((ULONG_PTR)TargetFunction + (sizeof(jmp) * jmpIndex)); \
    WriteToReadOnly(realTF, jmp, sizeof(jmp)); \
    jmpIndex += 1; \
    kDbgStatus("Final address 0x%p\n", realTF); \
    return realTF;}

#define Deploy_Custom_JMP_Pool(funcName,moduleName,Function) \
	PVOID modname(PVOID target) {\
    static ULONG_PTR jmpIndex = 0; \
    PVOID base = FindModule(moduleName); \
    PVOID TargetFunction = GetFunctionExport(base, Function); \
	SIZE_T size = JMPFixer::GetFunctionSize(TargetFunction); \
	if (size <= 12 * jmpIndex) { \
		kDbgError("WARNING: Appropriate size reached. Please find a new untriggered function! (size = %d) \n", 12 * jmpIndex); \
		return (PVOID)0xCCCCCC111; \
	} \
    if (!base) { \
        kDbg("Failed to find the base address of ntoskrnl.exe\n"); \
        return nullptr; \
    } \
    if (!TargetFunction) { \
        kDbg("Failed to find the target function in ntoskrnl.exe\n"); \
        return nullptr; \
    } \
    BYTE jmp[12]; \
    CraftJMP(target, jmp); \
    PVOID realTF = (PVOID)((ULONG_PTR)TargetFunction + (sizeof(jmp) * jmpIndex)); \
    WriteToReadOnly(realTF, jmp, sizeof(jmp)); \
    jmpIndex += 1; \
    kDbgStatus("Final address 0x%p\n", realTF); \
    return realTF;}

void callback(JMPINFO jmp, PVOID target) {
	JMPFixer::logJMP(jmp, target);
	PVOID start = jmp.startAddress;
	PVOID end = (PVOID)((ULONG_PTR)start + jmp.GeneralSize);
	if (jmp.IsShort == TRUE) {

		INT32 offset = ((INT32)jmp.offset - 5);
	//	kDbgStatus("SHORT::::::::::::::\nWRITING OFFSET FROM \n\t0x%X\n", jmp.offset);
		//kDbgStatus("TO: \n\t0x%X\n", offset);



	//	kDbgStatus("Addresses:\n\tstart: 0x%p", start);
	//	kDbgStatus("\n\tend: 0x%p\n", end);
		if (InRange(end,start,jmp.redirectAddress)) {
		//	kDbgStatus("THE OFFSET STANDS IN RANGE!!! 0x%p\n",jmp.redirectAddress);
		}
		else {
			//kDbgStatus("THE OFFSET OUT RANGE!!! 0x%p\n", jmp.redirectAddress);

			BYTE bt[2] = { jmp.JMPType,  offset };

			memcpy(jmp.jmpAddress, bt, 2);
		}



		return;
	}
	if (ISCALLJMP(jmp.JMPType)) {
		BYTE byte[JMP_SIZE];
		INT32 offset = (INT32)(jmp.offset - 5);


		if (InRange(end,start,jmp.redirectAddress)) {
		//	kDbgStatus("THE OFFSET STANDS IN RANGE LONGGGG!!! 0x%p\n", jmp.redirectAddress);
		}
		else {
		//	kDbgStatus("THE OFFSET OUT RANGE LONGGG!!! 0x%p\n", jmp.redirectAddress);

			JMPFixer::makeConditionalJMPs(byte, offset, jmp.JMPType);

			memcpy(jmp.jmpAddress, byte, JMP_SIZE);


		}

	//	kDbgStatus("WRITING OFFSET FROM \n\t0x%X\n", jmp.offset);
	//	kDbgStatus("TO: \n\t0x%X\n", offset);

	}
	else {
		BYTE byte[JMP_SIZE_CON];
		INT32 offset = (INT32)(jmp.offset - 5);

		if (((ULONG_PTR)end > (ULONG_PTR)jmp.redirectAddress) && ((ULONG_PTR)start <= (ULONG_PTR)jmp.redirectAddress)) {
		//	kDbgStatus("THE OFFSET STANDS IN RANGE LONGGGG!!! 0x%p\n", jmp.redirectAddress);
		}
		else {
		//	kDbgStatus("THE OFFSET OUT RANGE LONGGG!!! 0x%p\n", jmp.redirectAddress);


			JMPFixer::makeConditionalJMP(byte, offset, jmp.JMPType);
			memcpy(jmp.jmpAddress, byte, JMP_SIZE_CON);

		}



	}


}

void uncallback(JMPINFO jmp, PVOID target) {
	JMPFixer::logJMP(jmp, target);
	PVOID start = jmp.startAddress;
	PVOID end = (PVOID)((ULONG_PTR)start + jmp.GeneralSize);
	if (jmp.IsShort == TRUE) {

		INT32 offset = ((INT32)jmp.offset + 5);
		//	kDbgStatus("SHORT::::::::::::::\nWRITING OFFSET FROM \n\t0x%X\n", jmp.offset);
			//kDbgStatus("TO: \n\t0x%X\n", offset);



		//	kDbgStatus("Addresses:\n\tstart: 0x%p", start);
		//	kDbgStatus("\n\tend: 0x%p\n", end);
		if (InRange(end, start, jmp.redirectAddress)) {
			//	kDbgStatus("THE OFFSET STANDS IN RANGE!!! 0x%p\n",jmp.redirectAddress);
		}
		else {
			//kDbgStatus("THE OFFSET OUT RANGE!!! 0x%p\n", jmp.redirectAddress);

			BYTE bt[2] = { jmp.JMPType,  offset };

			memcpy(jmp.jmpAddress, bt, 2);
		}



		return;
	}
	if (ISCALLJMP(jmp.JMPType)) {
		BYTE byte[JMP_SIZE];
		INT32 offset = (INT32)(jmp.offset + 5);


		if (InRange(end, start, jmp.redirectAddress)) {
			//	kDbgStatus("THE OFFSET STANDS IN RANGE LONGGGG!!! 0x%p\n", jmp.redirectAddress);
		}
		else {
			//	kDbgStatus("THE OFFSET OUT RANGE LONGGG!!! 0x%p\n", jmp.redirectAddress);

			JMPFixer::makeConditionalJMPs(byte, offset, jmp.JMPType);

			memcpy(jmp.jmpAddress, byte, JMP_SIZE);


		}

		//	kDbgStatus("WRITING OFFSET FROM \n\t0x%X\n", jmp.offset);
		//	kDbgStatus("TO: \n\t0x%X\n", offset);

	}
	else {
		BYTE byte[JMP_SIZE_CON];
		INT32 offset = (INT32)(jmp.offset + 5);

		if (((ULONG_PTR)end > (ULONG_PTR)jmp.redirectAddress) && ((ULONG_PTR)start <= (ULONG_PTR)jmp.redirectAddress)) {
			//	kDbgStatus("THE OFFSET STANDS IN RANGE LONGGGG!!! 0x%p\n", jmp.redirectAddress);
		}
		else {
			//	kDbgStatus("THE OFFSET OUT RANGE LONGGG!!! 0x%p\n", jmp.redirectAddress);


			JMPFixer::makeConditionalJMP(byte, offset, jmp.JMPType);
			memcpy(jmp.jmpAddress, byte, JMP_SIZE_CON);

		}



	}


}

void UnGenCallback(GENADDRINFO info) {

	if (info.NMOD == 1 && info.RM == 1) {
		kDbgStatus("offset: %x\n", info.offset);
		kDbgStatus("postJMP: %p\n", info.postTargetAddress);
		kDbgStatus("target address: %p\n", info.TargetAddress);
		kDbgStatus("address: %p\n", info.address);
		kDbgStatus("Atomic: 0x%X\n", info.IsAtomicOperation);

		kDbgStatus("MODRM (BYTE): 0x%X\n", info.MODRMByte);

		kDbgStatus("\tMODRM (NMODRM) TRUE = 1, FALSE = 0: %p\n", info.NMOD);
		kDbgStatus("\tMODRM (RM)  TRUE = 1, FALSE = 0: %p\n", info.RM);


		PVOID end = (PVOID)((ULONG_PTR)info.startAddress + info.GeneralSize);
		if (InRange(end, info.startAddress, info.TargetAddress)) {
			kDbg("\n\nThis function stands in range, do not change.\n\n");
		}
		else {
			INT32 newOffset = (INT32)(info.offset + 5);

			kDbg("\n\nThis function out of range, needs a change\n");
			kDbgStatus("\n\tOld offset: 0x%X\n", info.offset);
			kDbgStatus("\n\tNew offset: 0x%X\n\n", newOffset);

			JMPFixer::makeOffset((BYTE*)((ULONG_PTR)info.address + OffsetAlignment(info.Is8Bit, info.IsAtomicOperation) + 1), newOffset);
		}

	}



}
/*
PVOID kmHookFunction(PVOID TargetFunction, PVOID HookedFunction, PVOID* originalFunction) {
	SIZE_T sizeFunction = JMPFixer::GetFunctionSize(TargetFunction, 0);

	PVOID backup = ExAllocatePool(NonPagedPool, sizeFunction);

	memcpy(backup, TargetFunction, sizeFunction);

	PVOID addr = kmCreateJMP(HookedFunction);

	INT32 offset = ((INT32)addr - (INT32)TargetFunction) - 5;

	kDbgStatus("The function offset is: 0x%p\n", offset);
	// basic comment
	BYTE conJmp[5];

	JMPFixer::makeConditionalJMPs(conJmp, offset, 0xe9);


	kDbgStatus("The function is in 0x%p\n", backup);
	kDbgStatus("size: %i\n", sizeFunction);

	PVOID preview = ExAllocatePool(NonPagedPool, sizeFunction + 6);

	kDbgStatus("The function looks like this: 0x%p\n", preview);

	memcpy(preview, conJmp, sizeof(conJmp));

	memcpy((PVOID)((ULONG_PTR)preview + 5), TargetFunction, sizeFunction);

	JMPFixer::WalkAddrFixerV2((PVOID)((ULONG_PTR)preview + 5), sizeFunction, callback, TargetFunction);
	//JMPFixer::WalkShortJMPs((PVOID)((ULONG_PTR)preview + 5), sizeFunction, callbackShort, TargetFunction);

	memcpy(preview, conJmp, sizeof(conJmp));

	*originalFunction = (PVOID)((ULONG_PTR)TargetFunction + 5);


	WriteToReadOnly(TargetFunction, (BYTE*)preview, sizeFunction + 5);
	//WriteToReadOnly((PVOID)((ULONG_PTR)TargetFunction + 5), (BYTE*)TargetFunction, sizeFunction);
	WriteToReadOnly(conJmp, (BYTE*)TargetFunction, sizeFunction);
	//ExFreePool(preview);

	return backup;
}
*/
void GenCallback(GENADDRINFO info) {

	if (info.NMOD == 1 && info.RM == 1) {
		kDbgStatus("offset: %x\n", info.offset);
		kDbgStatus("postJMP: %p\n", info.postTargetAddress);
		kDbgStatus("target address: %p\n", info.TargetAddress);
		kDbgStatus("address: %p\n", info.address);
		kDbgStatus("Atomic: 0x%X\n", info.IsAtomicOperation);

		kDbgStatus("MODRM (BYTE): 0x%X\n", info.MODRMByte);

		kDbgStatus("\tMODRM (NMODRM) TRUE = 1, FALSE = 0: %p\n", info.NMOD);
		kDbgStatus("\tMODRM (RM)  TRUE = 1, FALSE = 0: %p\n", info.RM);


		PVOID end = (PVOID)((ULONG_PTR)info.startAddress + info.GeneralSize);
		if (InRange(end, info.startAddress, info.TargetAddress)) {
			kDbg("\n\nThis function stands in range, do not change.\n\n");
		}
		else {
			INT32 newOffset = (INT32)(info.offset - 5);

			kDbg("\n\nThis function out of range, needs a change\n");
			kDbgStatus("\n\tOld offset: 0x%X\n", info.offset);
			kDbgStatus("\n\tNew offset: 0x%X\n\n", newOffset);

			JMPFixer::makeOffset((BYTE*)((ULONG_PTR)info.address + OffsetAlignment(info.Is8Bit,info.IsAtomicOperation) + 1), newOffset);
		}

	}



}


typedef PVOID(__stdcall* createJMP)(PVOID);

#define waitSec(b)	\
	LARGE_INTEGER b;\
	b.QuadPart = -10000000LL;\
	KeDelayExecutionThread(KernelMode, FALSE, &b);

PVOID KmFindByPattern(PVOID start, BYTE* pattern, const char* mask, SIZE_T size, SIZE_T MaxIndex = 0xFFA08) {
	SIZE_T maskLength = strlen(mask);
	SIZE_T len = min(maskLength, size);

	for (SIZE_T i = 0; i < MaxIndex; i++) {
		BYTE* address = (BYTE*)start + i;
		BOOLEAN found = TRUE;

		for (SIZE_T j = 0; j < len; j++) {
			if (mask[j] == 'x' && address[j] != pattern[j]) {
				found = FALSE;
				break;
			}
		}

		if (found) {
			kDbgStatus("Got address: 0x%p\n", address);
			return (PVOID)address;
		}
	}

	// Debug pattern dump
	for (SIZE_T i = 0; i < len; i++) {
		kDbgStatus("0x%02X %c\n", pattern[i], mask[i]);
	}

	return nullptr;
}


void kmHookFunctionEx(PVOID TargetFunction, PVOID HookedFunction, PVOID* originalFunction, createJMP kmCusJMP,PVOID* hookstored = 0) {

//	KIRQL oldIrql = KeGetCurrentIrql();

	SIZE_T sizeFunction = JMPFixer::GetFunctionSize(TargetFunction, 0);
	SIZE_T allsize = JMPFixer::GetFunctionSize(TargetFunction, 1);
	SIZE_T sizeofInt3 = allsize - sizeFunction;

	if (!(hookstored == 0)) {
		PVOID backup = ExAllocatePool(NonPagedPool, allsize);

		memcpy(backup, TargetFunction, allsize);

		*hookstored = backup;
	}



	if (sizeofInt3 < 5) {
		kDbgStatus("Not Enough INT3s (%d). Halting...\n", sizeofInt3);
		return;
	}


	PVOID addr = kmCusJMP(HookedFunction);

	if (addr == (PVOID)0xCCCCCC111) {
		return;
	}

	INT32 offset = ((INT32)addr - (INT32)TargetFunction) - 5;

	kDbgStatus("The function offset is: 0x%p\n", offset);
	// basic comment
	BYTE conJmp[5];

	JMPFixer::makeConditionalJMPs(conJmp, offset, 0xe9);

	kDbgStatus("size: %i\n", sizeFunction);

	PVOID preview = ExAllocatePool(NonPagedPool, sizeFunction + 6);

	kDbgStatus("The function looks like this: 0x%p\n", preview);

	memcpy(preview, conJmp, sizeof(conJmp));

	memcpy((PVOID)((ULONG_PTR)preview + 5), TargetFunction, sizeFunction);

	if (originalFunction != NULL) {
		JMPFixer::WalkAddrFixerV2((PVOID)((ULONG_PTR)preview + 5), sizeFunction, callback, TargetFunction);
		//JMPFixer::WalkShortJMPs((PVOID)((ULONG_PTR)preview + 5), sizeFunction, callbackShort, TargetFunction);

		JMPFixer::GeneralAddressFixer((PVOID)((ULONG_PTR)preview + 5), sizeFunction, GenCallback, TargetFunction);
	}
		






#ifndef KMHOOK_SAFETY_FEATURES_OFF
	KAFFINITY affinity = KeQueryActiveProcessors();
	KeSetSystemAffinityThreadEx(affinity);  // Make sure we run on a single core
#endif

//	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);  // Prevent task switches

	kDbg("Raised irql to DISPATCH_LEVEL and running single core... + Pausing cpu.\n");

	memcpy(preview, conJmp, sizeof(conJmp));


	if (originalFunction != NULL)

		*originalFunction = (PVOID)((ULONG_PTR)TargetFunction + 5);


	WriteToReadOnly(TargetFunction, (BYTE*)preview, sizeFunction + 5);  //UNCOMMENT

	waitSec(c);

	//InvalidateCPUCache();

	//kDbg("Restoring processors.\n");


//	KeLowerIrql(0);
#ifndef KMHOOK_SAFETY_FEATURES_OFF
	KeRevertToUserAffinityThreadEx(affinity);
#endif
	kDbg("Returning...");

	ExFreePool(preview);

	waitSec(a);



}
void kmHookFunction(PVOID TargetFunction, PVOID HookedFunction, PVOID* originalFunction,PVOID* hookstored = 0) {
	kmHookFunctionEx(TargetFunction, HookedFunction, originalFunction, kmCreateJMP, hookstored);
}

void kmUnhookFunction(PVOID TargetFunction, PVOID hookstored) {

	WriteToReadOnly(TargetFunction, (BYTE*)hookstored, JMPFixer::GetFunctionSize(hookstored));
}
BOOLEAN kmIsHooked(PVOID TargetFunction) {
	return (MmIsAddressValid(TargetFunction)) ? (*(BYTE*)(TargetFunction) == 0xe9) : FALSE;
}
void kmUnhookFunctionEx(PVOID TargetFunction, SIZE_T size = 0) {

	if (!kmIsHooked(TargetFunction))
		return; // No need for unhooking.

	SIZE_T sizeFunction = (size == 0) ? JMPFixer::GetFunctionSize((PVOID)((ULONG_PTR)TargetFunction + 5), 1) : size;

	PVOID preview = ExAllocatePool(NonPagedPool, sizeFunction + 5);

	memcpy(preview, (PVOID)((ULONG_PTR)TargetFunction + 5),sizeFunction);

	kDbgStatus("unhook preview: %p\n", preview);

	JMPFixer::WalkAddrFixerV2(preview, sizeFunction, uncallback, NULL);
	JMPFixer::GeneralAddressFixer(preview, sizeFunction, UnGenCallback, NULL);
	
	RtlFillMemory((PVOID)((ULONG_PTR)preview + sizeFunction), 5, 0xCC);

	kDbgStatus("Fill : %p\n", (PVOID)((ULONG_PTR)preview + sizeFunction));

	WriteToReadOnly(TargetFunction, (BYTE*)preview, sizeFunction + 5);

}

