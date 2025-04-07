// Purpose, hook functions.
// uses CarCopyRuleViolationDetails as a pool as its not used anymore.

// Offset formula: (JmpTo - JmpFrom) - 5

//ed nt!Kd_IHVDRIVER_Mask 8

#include "kmHook.h"


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
		return;
	}

	if (!NT_SUCCESS(MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE))) {
		kDbg("Failed to apply protection for MDL.\n");
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

	PVOID realTF = (PVOID)((ULONG_PTR)target + (sizeof(jmp) * jmpIndex));

	WriteToReadOnly(realTF, jmp, sizeof(jmp));

	jmpIndex += 1;

	

	return realTF;
}
void callback(JMPINFO jmp, PVOID target) {
	JMPFixer::logJMP(jmp, target);

	PVOID original = GET_ORIGINAL(jmp, target);
	PVOID postJMPoriginal = GET_POSTJMP_ORIGINAL(jmp, target);
	PVOID origRedirect = GET_REDIRECT_ADDRESS_ORIGINAL(jmp, target);

	if (jmp.IsShort == TRUE) {

		INT32 offset = ((INT32)jmp.offset - 5);
		kDbgStatus("SHORT::::::::::::::\nWRITING OFFSET FROM \n\t0x%X\n", jmp.offset);
		kDbgStatus("TO: \n\t0x%X\n", offset);
		
		BYTE bt[2] = { jmp.JMPType,  offset};

		memcpy(jmp.jmpAddress, bt, 2);

		return;
	}
	if (ISCALLJMP(jmp.JMPType)) {
		BYTE byte[JMP_SIZE];
		INT32 offset = (INT32)(jmp.offset - 5);

		JMPFixer::makeConditionalJMPs(byte, offset, jmp.JMPType);

		memcpy(jmp.jmpAddress, byte, JMP_SIZE);

		kDbgStatus("WRITING OFFSET FROM \n\t0x%X\n", jmp.offset);
		kDbgStatus("TO: \n\t0x%X\n", offset);

	}
	else {
		BYTE byte[JMP_SIZE_CON];
		INT32 offset = (INT32)(jmp.offset - 5);

		JMPFixer::makeConditionalJMP(byte, offset, jmp.JMPType);

		memcpy(jmp.jmpAddress, byte, JMP_SIZE_CON);
	}


}

void callbackShort(JMPINFO info, PVOID target) {
	kDbg("\t\tSHORT FOUND::::::::::::::::::::::::::::::::::\n");
	JMPFixer::logJMP(info, target);
}
PVOID kmHookFunction(PVOID TargetFunction, PVOID HookedFunction,PVOID* originalFunction) {
	SIZE_T sizeFunction = JMPFixer::GetFunctionSize(TargetFunction, 0);

	PVOID backup = ExAllocatePool(NonPagedPool, sizeFunction);

	memcpy(backup, TargetFunction, sizeFunction);

	PVOID addr = kmCreateJMP(HookedFunction);

	INT32 offset = ((INT32)addr - (INT32)TargetFunction) - 5;

	kDbgStatus("The function offset is: 0x%p\n", offset);

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
	//WriteToReadOnly(conJmp, (BYTE*)TargetFunction, sizeFunction);
	ExFreePool(preview);

	return backup;
}
