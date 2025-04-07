// Taken from my previous project.
// Made by nu11ptr.


#pragma once
#include "resource.h"

#define JMP_SIZE 5
#define JMP_SIZE_CON 6
#define GET_ORIGINAL(info, target) (PVOID)((LONG_PTR)target + (LONG_PTR)info.position)
#define modRM_IS_RM(byte) (((UINT64)byte & 0x7) == 5)
#define modRM_IS_NMOD(byte) (((UINT64)byte >> 7) == 0)
#define InRange(end,start,target) ((ULONG_PTR)end > (ULONG_PTR)target) && ((ULONG_PTR)start <= (ULONG_PTR)target)
#define GET_POSTJMP_ORIGINAL(info,target) (PVOID)(((LONG_PTR)target + info.postJMPOffset))
#define GET_REDIRECT_ADDRESS_ORIGINAL(info,target) (PVOID)(((LONG_PTR)GET_POSTJMP_ORIGINAL(info,target) + (INT32)info.offset))
#define ISSHORTJMP(Byte) ((Byte) == 0xEB || ((Byte) >= 0x70 && (Byte) <= 0x7F))
#define CALLJMP(Byte) (Byte != 0xe8 && Byte != 0xe9)
#define ISCALLJMP(Byte) (Byte == 0xe8 || Byte == 0xe9)
#define OffsetAlignment(is8Bit,IsAtomicOperation)  ((!is8Bit) ? ((!IsAtomicOperation) ? 1 : 3 ) : (is8Bit) ? 2 : 0)
#define IsModRmCompatible(info) ( \
    (info.id == X86_INS_MOV)     || (info.id == X86_INS_MOVZX)   || \
    (info.id == X86_INS_MOVSX)   || (info.id == X86_INS_MOVSXD)  || \
    (info.id == X86_INS_XCHG)    || (info.id == X86_INS_CMPXCHG) || \
    (info.id == X86_INS_XADD)    || (info.id == X86_INS_ADD)     || \
    (info.id == X86_INS_SUB)     || (info.id == X86_INS_ADC)     || \
    (info.id == X86_INS_SBB)     || (info.id == X86_INS_MUL)     || \
    (info.id == X86_INS_IMUL)    || (info.id == X86_INS_DIV)     || \
    (info.id == X86_INS_IDIV)    || (info.id == X86_INS_INC)     || \
    (info.id == X86_INS_DEC)     || (info.id == X86_INS_NEG)     || \
    (info.id == X86_INS_NOT)     || (info.id == X86_INS_AND)     || \
    (info.id == X86_INS_OR)      || (info.id == X86_INS_XOR)     || \
    (info.id == X86_INS_TEST)    || (info.id == X86_INS_CMP)     || \
    (info.id == X86_INS_BT)      || (info.id == X86_INS_BTS)     || \
    (info.id == X86_INS_BTR)     || (info.id == X86_INS_BTC)     || \
    (info.id == X86_INS_SHL)     || (info.id == X86_INS_SHR)     || \
    (info.id == X86_INS_SAR)     || (info.id == X86_INS_SAL)     || \
    (info.id == X86_INS_RCL)     || (info.id == X86_INS_RCR)     || \
    (info.id == X86_INS_ROL)     || (info.id == X86_INS_ROR)     || \
    (info.id == X86_INS_LEA)     || (info.id == X86_INS_BOUND)   || \
    (info.id == X86_INS_LGS)     || (info.id == X86_INS_LSS)     || \
    (info.id == X86_INS_LDS)     || (info.id == X86_INS_LES)     || \
    (info.id == X86_INS_LFS)     || (info.id == X86_INS_LGDT)    || \
    (info.id == X86_INS_LIDT)    || (info.id == X86_INS_SGDT)    || \
    (info.id == X86_INS_SIDT)    || (info.id == X86_INS_STR)     || \
    (info.id == X86_INS_SLDT)    || (info.id == X86_INS_LTR)     || \
    (info.id == X86_INS_VERR)    || (info.id == X86_INS_VERW)    || \
    (info.id == X86_INS_ARPL)    || (info.id == X86_INS_CLTS)    || \
    (info.id == X86_INS_LMSW)    || (info.id == X86_INS_SMSW)    || \
    (info.id == X86_INS_INVLPG)  || (info.id == X86_INS_FLD)     || \
    (info.id == X86_INS_FST)     || (info.id == X86_INS_FSTP)    || \
    (info.id == X86_INS_FILD)    || (info.id == X86_INS_FISTP)   || \
    (info.id == X86_INS_FIST)    || (info.id == X86_INS_FLDCW)   || \
    (info.id == X86_INS_FNSTCW)  || (info.id == X86_INS_FFREE)   || \
    (info.id == X86_INS_FNSTSW) )



#define ADFIXER_VAL_NOT_FOUND  -1120334667
#define ISJMPD(info) ( \
    (info.id == X86_INS_JAE)   || (info.id == X86_INS_JA)   || \
    (info.id == X86_INS_JBE)   || (info.id == X86_INS_JB)   || \
    (info.id == X86_INS_JCXZ)  || (info.id == X86_INS_JECXZ)|| \
    (info.id == X86_INS_JE)    || (info.id == X86_INS_JGE)  || \
    (info.id == X86_INS_JG)    || (info.id == X86_INS_JLE)  || \
    (info.id == X86_INS_JL)    || (info.id == X86_INS_JMP)  || \
    (info.id == X86_INS_JNE)   || (info.id == X86_INS_JNO)  || \
    (info.id == X86_INS_JNP)   || (info.id == X86_INS_JNS)  || \
    (info.id == X86_INS_JO)    || (info.id == X86_INS_JP)   || \
    (info.id == X86_INS_JRCXZ) || (info.id == X86_INS_JS)   || \
    (info.id == X86_INS_LCALL) || (info.id == X86_INS_CALL) || \
    (info.id == X86_INS_LJMP))


// little endian to big endian macro.

#define flip(input) ((((ULONG_PTR)input >> 8) & 0xFF) << 24) + \
    ((((ULONG_PTR)input >> 8 >> 8) & 0xFF) << 16) + \
    ((((ULONG_PTR)input >> 8 >> 8 >> 8) & 0xFF) << 8) + \
    ((((ULONG_PTR)input >> 8 >> 8 >> 8 >> 8) & 0xFF))

#define IsJMP(byte) ((ULONG_PTR)(byte) >= 0x80 && \
    (ULONG_PTR)(byte) <= 0x90)

// Turns from AB CD EF to 0xABCDEF 
#define ToBinCode(b1,b2,b3,b4,b5) (((UINT64)(b1) << 32) + \
    ((UINT64)(b2) << 24) + \
    ((UINT64)(b3) << 16) + \
    ((UINT64)(b4) << 8) + \
    (UINT64)(b5))

#define ToLittleEdian(val) ((((UINT32)(val) & 0xFF) << 24) | \
                            ((((UINT32)(val) >> 8) & 0xFF) << 16) | \
                            ((((UINT32)(val) >> 16) & 0xFF) << 8) | \
                            (((UINT32)(val) >> 24) & 0xFF))

typedef struct {
	ULONG size;
	PVOID addr;
	char* name;

	union {
		char* nameNext;
		PVOID addrNext;


	} NextInfo;
} funcInfo;

typedef void(__stdcall* fcallbackret)(PVOID, ULONG, PVOID);

typedef struct {
	ULONG JMPType;
	PVOID redirectAddress;
	INT32 offset;
	ULONG valid;
	ULONG position;
	PVOID jmpAddress;
	PVOID postJMPAddress;
	ULONG postJMPOffset;
	BOOLEAN IsShort = 0;
	SIZE_T GeneralSize = 0;
	PVOID startAddress = nullptr;
}JMPINFO;

typedef struct {
	PVOID TargetAddress;
	INT32 offset;
	PVOID postTargetAddress;
	PVOID address;
	BOOLEAN Is8Bit;
	BYTE MODRMByte;
	BOOLEAN NMOD;
	BOOLEAN RM;
	PVOID startAddress = nullptr;
	SIZE_T insnSize;
	BOOLEAN IsAtomicOperation;
	SIZE_T GeneralSize = 0;

} GENADDRINFO;
typedef void(__stdcall* fNCallback)(

	JMPINFO info, PVOID target
	);

typedef void(__stdcall* fNGCallback)(

	GENADDRINFO info
	);
typedef struct {
	ULONG JMPType;
	PVOID redirectAddress;
	INT32 offset;
	ULONG valid;
	ULONG position;
	PVOID jmpAddress;
	PVOID postJMPAddress;
	ULONG postJMPOffset;
}JMPINFOv2;
typedef void(__stdcall* fNCallbackv2)(

	JMPINFOv2 info, PVOID target
	);

namespace JMPFixer {
	BOOLEAN IsJMPInstruction(ULONG position, BYTE* buf) {
		BYTE jmp[] = { 0x75 , 0x0f83 };
		if ((*(BYTE*)((ULONG_PTR)buf + position + sizeof(BYTE)) == 0x83) &&
			*(BYTE*)((ULONG_PTR)buf + position) == 0x0f) {
			//jae instruction


		}
		return 1;
	}
	void makeConditionalJMP(BYTE* dest, ULONG offset, ULONG JMPType) {
		BYTE modification[] = { 0xF,JMPType,0x00,0x00,0x00,0x00 };
		for (ULONG i = 0; i < 4; i++)
			*(BYTE*)(modification + (sizeof(BYTE) * 2) + i) = (offset >> (8 * i)) & 0xFF;

		memcpy(dest, modification, sizeof(modification));

	}

	INT32 GetOffsetFromBytes(cs_insn insn,BOOLEAN jmp = 0) {
		PVOID address = reinterpret_cast<PVOID>(insn.address);
		SIZE_T size = insn.size;
		ULONG_PTR offset = 0x00000000;
		BOOLEAN is8Bit = (
			*(BYTE*)(address) <= 0x50
			);
		BOOLEAN isAtomic = (
			*(BYTE*)(address) == 0xf0
			);

		for (ULONG i = 0; i < 4; i++) {
			BYTE byte = (jmp == 0) ? *(BYTE*)((ULONG_PTR)address + (OffsetAlignment(is8Bit,isAtomic) + 1) + i)
				
				: (insn.bytes[0] == 0x0f) ? *(BYTE*)((ULONG_PTR)address + 2 + i) : *(BYTE*)((ULONG_PTR)address + 1 + i); //8b0598827b00       mov     eax, dword ptr [ntkrnlmp!HvlpFlags (fffff80770b1da50)]

			printf("0x%x\n", byte);
			offset = (offset + byte) << 8;

		}
		// grab 4 bytes

		printf("offset lol: 0x%x\n", (INT32)(offset >> 8));

		return ToLittleEdian((INT32)(offset >> 8));
	}

	_IRQL_requires_max_(APC_LEVEL)
		JMPINFO transformJMP(PVOID nextAddr, ULONG Byte, ULONG next, ULONG pos, PVOID start) {

		BYTE b2 = *(BYTE*)((ULONG_PTR)nextAddr + 1);
		BYTE b3 = *(BYTE*)((ULONG_PTR)nextAddr + 2);
		BYTE b4 = *(BYTE*)((ULONG_PTR)nextAddr + 3);
		BYTE b5 = *(BYTE*)((ULONG_PTR)nextAddr + 4);

		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 3, "Byte JMP bytes:: B1: 0x%X\nB2: 0x%X\nB3: 0x%X\nB4: 0x%X\nB5: 0x%X\n", next, b2, b3, b4, b5);
		UINT64 translation = ToBinCode(Byte, next, b2, b3, b4);

		PVOID postJMPAddr = CALLJMP(Byte) ?
			(PVOID)((ULONG_PTR)nextAddr + 5) :
			(PVOID)((ULONG_PTR)nextAddr + 4);

		ULONG_PTR offset = CALLJMP(Byte) ?
			flip(translation << 8) >> 8 :
			flip(translation << 8);
		INT32 signedOffset = (INT32)offset;

		kDbgStatus("%d\n", signedOffset);

		PVOID redirectAddress = (PVOID)((ULONG_PTR)postJMPAddr + signedOffset);

		JMPINFO info = {
			CALLJMP(Byte) ? next : Byte,
			redirectAddress,
			signedOffset,
			1,
			pos - 1,

			(PVOID)((ULONG_PTR)start + (pos * sizeof(BYTE)) - sizeof(BYTE)),
			postJMPAddr,
			(ULONG_PTR)postJMPAddr - (ULONG_PTR)start

		};
		return info;

	}
	JMPINFO getJMPInfo(PVOID start) {
		BYTE Byte = *(BYTE*)(start);
		BYTE next = *(BYTE*)((ULONG_PTR)start + 1);
		PVOID nextAddr = (PVOID)((ULONG_PTR)start + 1);
		return transformJMP(nextAddr, Byte, next, 1, start);
	}
	void logJMP(JMPINFO info, PVOID target) {
		PVOID original = GET_ORIGINAL(info, target);
		PVOID postJMPoriginal = GET_POSTJMP_ORIGINAL(info, target);


		kDbgStatus("original JMP: 0x%p\n", original);
		kDbgStatus("postJMPoriginal JMP: 0x%p\n", postJMPoriginal);

		kDbgStatus("JMPType: 0x%X\n", info.JMPType);
		kDbgStatus("redirectAddress: %p\n", GET_REDIRECT_ADDRESS_ORIGINAL(info, target));
		kDbgStatus("redirectAddressOriginal: %p\n", info.redirectAddress);
		kDbgStatus("offset: 0x%X\n", info.offset);
		kDbgStatus("valid: %lu\n", info.valid);
		kDbgStatus("position: %d\n", info.position);
		kDbgStatus("jmpAddress: %p\n", info.jmpAddress);
		kDbgStatus("post jmp : %p\n", info.postJMPAddress);
		kDbgStatus("post jmp offset: %d\n", info.postJMPOffset);

	}
	void WalkAddrFixer(PVOID start, SIZE_T size, fNCallback callback, PVOID Target) { // Not working. use the other version.
		BYTE Byte;
		BYTE next;
		PVOID nextAddr;
		int pos = -1;

		Byte = *(BYTE*)((ULONG_PTR)start);
		next = *(BYTE*)((ULONG_PTR)start + 1);
		nextAddr = (PVOID)((ULONG_PTR)start + 1);

		while (++pos <= size) {

			if ((Byte == 0xf && IsJMP(next)) || (Byte == 0xe8 || Byte == 0xe9)) {

				JMPINFO jmp = transformJMP(nextAddr, Byte, next, pos, start);
				callback(jmp, Target);
			}

			Byte = *(BYTE*)((ULONG_PTR)start + (pos * sizeof(BYTE)));
			next = *(BYTE*)((ULONG_PTR)start + (pos * sizeof(BYTE)) + 1);
			nextAddr = (PVOID)((ULONG_PTR)start + (pos * sizeof(BYTE)) + 1);
		}

	}

	ULONG GetFunctionSize(PVOID addr, ULONG IncludeInt3 = 1, ULONG countAttempt = -1) {
		BYTE bfByte;
		BYTE bfByteNext;
		int position = 0;
		int size = 0;
		bfByte = *(BYTE*)((ULONG_PTR)addr + position);
		bfByteNext = *(BYTE*)((ULONG_PTR)addr + (position + sizeof(BYTE))); // Next byte 
		while (!(bfByte == 0xCC && bfByteNext == 0xCC)) {

			if (countAttempt != -1 && countAttempt <= size)
				break;
			//kDbgStatus("The byte is 0x%X\n", bfByte);
		//	kDbgStatus("The next byte is 0x%X\n", bfByteNext);

			bfByte = *(BYTE*)((ULONG_PTR)addr + (++position));
			bfByteNext = *(BYTE*)((ULONG_PTR)addr + (position + sizeof(BYTE))); // Next byte 
			size++;

		}

		if (IncludeInt3 == 1) {
			while (!(bfByte != 0xCC)) {


				bfByte = *(BYTE*)((ULONG_PTR)addr + (++position));
				bfByteNext = *(BYTE*)((ULONG_PTR)addr + (position + sizeof(BYTE))); // Next byte 
				size++;
			}
		}

		return size;
	}
	void makeConditionalJMPs(BYTE* dest, ULONG offset, ULONG JMPType) {
		BYTE modification[] = { JMPType,0x00,0x00,0x00,0x00 };
		for (ULONG i = 0; i < 4; i++)
			*(BYTE*)(modification + sizeof(BYTE) + i) = (offset >> (8 * i)) & 0xFF;

		memcpy(dest, modification, sizeof(modification));

	}
	void makeOffset(BYTE* dest, ULONG offset) {
		BYTE modification[] = { 0x00,0x00,0x00,0x00 };
		for (ULONG i = 0; i < 4; i++)
			*(BYTE*)(modification + i) = (offset >> (8 * i)) & 0xFF;

		memcpy(dest, modification, sizeof(modification));

	}
	JMPINFO TransformShort(int pos, PVOID start, BYTE byte, BYTE next) {
		PVOID JMPAddress = (PVOID)((ULONG_PTR)start + pos);
		PVOID postJMPAddress = (PVOID)((ULONG_PTR)JMPAddress + 2);
		BYTE offset = *(BYTE*)(next);
		BYTE JMPType = *(BYTE*)(JMPAddress);
		PVOID Redirect = (PVOID)((ULONG_PTR)postJMPAddress + (INT32)offset);
		JMPINFO jmp = {
			JMPType,Redirect,(INT32)offset,1,pos,JMPAddress,postJMPAddress,pos + 2
		};

		return jmp;
	}

	void WalkShortJMPs(PVOID start, SIZE_T size, fNCallback callback, PVOID Target) {
		BYTE Byte;
		BYTE next;
		PVOID nextAddr;
		int pos = -1;

		Byte = *(BYTE*)((ULONG_PTR)start);
		next = *(BYTE*)((ULONG_PTR)start + 1);
		nextAddr = (PVOID)((ULONG_PTR)start + 1);

		while (++pos <= size) {

			kDbgStatus("BYTE:: 0x%X\n", Byte);

			if ((Byte == 0xf && IsJMP(next))) {

				pos += 6;
			}

			else if ((Byte == 0xe8 || Byte == 0xe9)) {
				pos += 5;
			}

			if (ISSHORTJMP(Byte)) {

				JMPINFO jmp = TransformShort(pos, start, Byte, next);
				callback(jmp, Target);
			}
			Byte = *(BYTE*)((ULONG_PTR)start + (pos * sizeof(BYTE)));
			next = *(BYTE*)((ULONG_PTR)start + (pos * sizeof(BYTE)) + 1);
			nextAddr = (PVOID)((ULONG_PTR)start + (pos * sizeof(BYTE)) + 1);
		}

	}


	static NTSTATUS WalkAddrFixerV2(PVOID start, SIZE_T size, fNCallback call, PVOID target) {
		csh handle;
		cs_insn* insn;
		size_t count;
		KFLOATING_SAVE float_save;
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		cs_driver_mm_init();
		// Ensure the current IRQL is less than or equal to DISPATCH_LEVEL
		NT_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

		// Save the current floating-point state
		status = KeSaveFloatingPointState(&float_save);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		// Initialize the Capstone disassembly engine for x86-64 architecture
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
			goto exit;
		}
		cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

		// Disassemble the code starting from the 'start' address
		count = cs_disasm(handle, (uint8_t*)start, (uint32_t)size, (uint64_t)start, 0, &insn);
		if (count > 0) {
			for (SIZE_T i = 0; i < count; i++) {
				cs_insn current = insn[i];

				// Print the instruction's address, mnemonic, and operand string
			//	DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_INFO_LEVEL,"op_str: \t%p\t%s\t%s\n", current.address, current.mnemonic, current.op_str);

				// Check if the instruction is a jump and its size is greater than 2
				if (ISJMPD(current) && current.size > 2) {
					//UINT64 translation = ToBinCode(current.bytes[0], current.bytes[1], current.bytes[2], current.bytes[3], current.bytes[4]);

					INT32 offset = GetOffsetFromBytes(current, 1); //CALLJMP(current.bytes[0]) ?
						//flip(translation << 8) >> 8 :
						//flip(translation << 8);

					JMPINFO jmp = { 0 };

					jmp.jmpAddress = (PVOID)current.address;
					jmp.JMPType = (current.bytes[0] == 0x0f) ? current.bytes[1] : current.bytes[0];
					jmp.postJMPAddress = (PVOID)((LONG_PTR)jmp.jmpAddress + current.size);
					jmp.offset = (INT32)offset;
					jmp.startAddress = start;
					jmp.redirectAddress = (PVOID)((LONG_PTR)jmp.postJMPAddress + (INT32)offset);
					jmp.position = (ULONG_PTR)current.address - (ULONG_PTR)start;
					jmp.postJMPOffset = (ULONG_PTR)jmp.postJMPAddress - (ULONG_PTR)start;
					jmp.valid = TRUE;
					jmp.GeneralSize = size;
					jmp.IsShort = FALSE;
					// Call the provided callback function with the jump information
					call(jmp, target);
				}
				else if (ISJMPD(current) && current.size == 2) {
					JMPINFO jmp = { 0 };

					jmp.IsShort = TRUE;
					jmp.GeneralSize = size;
					jmp.startAddress = start;
					jmp.jmpAddress = (PVOID)current.address;
					jmp.JMPType = current.bytes[0];
					jmp.postJMPAddress = (PVOID)((ULONG_PTR)jmp.jmpAddress + current.size);
					jmp.offset = (INT8)current.bytes[1];
					jmp.redirectAddress = (PVOID)((LONG_PTR)jmp.postJMPAddress + (INT8)jmp.offset);
					jmp.position = (ULONG_PTR)current.address - (ULONG_PTR)start;
					jmp.postJMPOffset = (ULONG_PTR)jmp.postJMPAddress - (ULONG_PTR)start;
					jmp.valid = TRUE;

					// Call the provided callback function with the jump information
					call(jmp, target);
				}
			}
			cs_free(insn, count);
		}

		cs_close(&handle);
		status = STATUS_SUCCESS;

	exit:
		// Restore the saved floating-point state
		KeRestoreFloatingPointState(&float_save);
		return status;
	}

	void initialize(GENADDRINFO info, cs_insn current,PVOID start) {
		info.GeneralSize = current.size;
		info.startAddress = start;
		info.address = (PVOID)current.address;
		info.postTargetAddress = (PVOID)((ULONG_PTR)current.address + current.size);
		info.offset = GetOffsetFromBytes(current);
		info.TargetAddress = (PVOID)((LONG_PTR)info.postTargetAddress + info.offset);
	}
	static NTSTATUS GeneralAddressFixer(PVOID start, SIZE_T size, fNGCallback call, PVOID target) {
		csh handle;
		cs_insn* insn;
		size_t count;
		KFLOATING_SAVE float_save;
		NTSTATUS status = STATUS_UNSUCCESSFUL;


		cs_driver_mm_init();
		// Ensure the current IRQL is less than or equal to DISPATCH_LEVEL
		NT_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

		// Save the current floating-point state
		status = KeSaveFloatingPointState(&float_save);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		// Initialize the Capstone disassembly engine for x86-64 architecture
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
			goto exit;
		}
		cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
		// Disassemble the code starting from the 'start' address
		count = cs_disasm(handle, (uint8_t*)start, (uint32_t)size, (uint64_t)start, 0, &insn);
		if (count > 0) {
			for (SIZE_T i = 0; i < count; i++) {
				cs_insn current = insn[i];

				// Print the instruction's address, mnemonic, and operand string
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "MOV OP STRING ID: %d: \t%p\t%s\t%s\n", current.id,current.address, current.mnemonic, current.op_str);

				if (IsModRmCompatible(current) && current.size >= 6) {
					GENADDRINFO info{ 0 };
					BOOLEAN is8Bit = (
						current.bytes[0] <= 0x50
						);
					BOOLEAN IsAtomicOperation = (
						current.bytes[0] == 0xf0
						);
					info.insnSize = current.size;
					info.startAddress = start;
					info.address = (PVOID)current.address;
					info.postTargetAddress = (PVOID)((ULONG_PTR)current.address + current.size);
					info.offset = GetOffsetFromBytes(current);
					info.TargetAddress = (PVOID)((LONG_PTR)info.postTargetAddress + info.offset);
					info.MODRMByte = *(BYTE*)((ULONG_PTR)current.address + OffsetAlignment(is8Bit,IsAtomicOperation) );

					kDbgStatus("ModRM: 0x%X\n", info.MODRMByte);

					info.NMOD = modRM_IS_NMOD(info.MODRMByte);
					info.Is8Bit = is8Bit;
					info.IsAtomicOperation = IsAtomicOperation;
					info.RM = modRM_IS_RM(info.MODRMByte);
					info.GeneralSize = size;
					call(info);

				}
				// Check if the instruction is a jump and its size is greater than 2
				
			}
			cs_free(insn, count);
		}

		cs_close(&handle);
		status = STATUS_SUCCESS;

	exit:
		// Restore the saved floating-point state
		KeRestoreFloatingPointState(&float_save);
		return status;
	}
}
