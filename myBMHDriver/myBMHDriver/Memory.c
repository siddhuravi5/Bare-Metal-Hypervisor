#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "MSR.h"
#include "BMHDriver_CPU.h"
#include "VMX.h"

#define ALIGNMENT_PAGE_SIZE   4096
#define MAXIMUM_ADDRESS	0xffffffffffffffff
#define VMCS_SIZE   4096
#define VMXON_SIZE   4096

UINT64 VirtualAddress_to_PhysicalAddress(void* va)
{
	return MmGetPhysicalAddress(va).QuadPart;
}

PVOID PhysicalAddress_to_VirtualAddress(UINT64 pa)
{
	PHYSICAL_ADDRESS PhysicalAddr;
	PhysicalAddr.QuadPart = pa;

	return MmGetVirtualForPhysical(PhysicalAddr);
}


BOOLEAN Allocate_VMXON_Region(IN PVirtualMachineState vmState)
{
	// at IRQL > DISPATCH_LEVEL memory allocation routines don't work
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();


	PHYSICAL_ADDRESS PhysicalMax = { 0 };
	PhysicalMax.QuadPart = MAXULONG64;


	int VMXONSize = 2 * VMXON_SIZE;
	BYTE* Buffer = MmAllocateContiguousMemory(VMXONSize + ALIGNMENT_PAGE_SIZE, PhysicalMax);  // Allocating a 4-KByte Contigous Memory region

	PHYSICAL_ADDRESS Highest = { 0 }, Lowest = { 0 };
	Highest.QuadPart = ~0;

	//BYTE* Buffer = MmAllocateContiguousMemorySpecifyCache(VMXONSize + ALIGNMENT_PAGE_SIZE, Lowest, Highest, Lowest, MmNonCached);

	if (Buffer == NULL) {
		DbgPrint("Error Allocating Buffer for VMXON Region. \n");
		return FALSE;// ntStatus = STATUS_INSUFFICIENT_RESOURCES;
	}
	UINT64 PhysicalBuffer = VirtualAddress_to_PhysicalAddress(Buffer);

	// zero-out memory 
	RtlSecureZeroMemory(Buffer, VMXONSize + ALIGNMENT_PAGE_SIZE);
	UINT64 alignedPhysicalBuffer = ((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

	UINT64 alignedVirtualBuffer = ((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

	DbgPrint("Virtual allocated buffer for VMXON is at %llx \n", Buffer);
	DbgPrint("Virtual aligned allocated buffer for VMXON is at %llx \n", alignedVirtualBuffer);
	DbgPrint("Aligned physical buffer allocated for VMXON is at %llx \n", alignedPhysicalBuffer);

	// get IA32_VMX_BASIC_MSR RevisionId

	IA32_VMX_BASIC_MSR basic = { 0 };


	basic.All = __readmsr(MSR_IA32_VMX_BASIC);

	DbgPrint("MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx \n", basic.Fields.RevisionIdentifier);

	//Changing Revision Identifier
	*(UINT64*)alignedVirtualBuffer = basic.Fields.RevisionIdentifier;


	int status = __vmx_on(&alignedPhysicalBuffer);
	if (status)
	{
		DbgPrint("VMXON failed with status %d\n", status);
		return FALSE;
	}

	vmState->VMXON_REGION = alignedPhysicalBuffer;

	return TRUE;
}

BOOLEAN Allocate_VMCS_Region(IN PVirtualMachineState vmState)
{
	// at IRQL > DISPATCH_LEVEL memory allocation routines don't work
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();


	PHYSICAL_ADDRESS PhysicalMax = { 0 };
	PhysicalMax.QuadPart = MAXULONG64;


	int VMCSSize = 2 * VMCS_SIZE;
	BYTE* Buffer = MmAllocateContiguousMemory(VMCSSize + ALIGNMENT_PAGE_SIZE, PhysicalMax);  // Allocating a 4-KByte Contigous Memory region

	PHYSICAL_ADDRESS Highest = { 0 }, Lowest = { 0 };
	Highest.QuadPart = ~0;

	//BYTE* Buffer = MmAllocateContiguousMemorySpecifyCache(VMXONSize + ALIGNMENT_PAGE_SIZE, Lowest, Highest, Lowest, MmNonCached);

	UINT64 PhysicalBuffer = VirtualAddress_to_PhysicalAddress(Buffer);
	if (Buffer == NULL) {
		DbgPrint("Error allocating Buffer for VMCS Region. \n");
		return FALSE;// ntStatus = STATUS_INSUFFICIENT_RESOURCES;
	}
	// zero-out memory 
	RtlSecureZeroMemory(Buffer, VMCSSize + ALIGNMENT_PAGE_SIZE);
	UINT64 alignedPhysicalBuffer = ((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

	UINT64 alignedVirtualBuffer = ((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));



	DbgPrint("Virtual allocated buffer for VMCS is at %llx \n", Buffer);
	DbgPrint("Virtual aligned allocated buffer for VMCS is at %llx \n", alignedVirtualBuffer);
	DbgPrint("Aligned physical buffer allocated for VMCS is at %llx \n", alignedPhysicalBuffer);

	// get IA32_VMX_BASIC_MSR RevisionId

	IA32_VMX_BASIC_MSR basic = { 0 };


	basic.All = __readmsr(MSR_IA32_VMX_BASIC);

	DbgPrint("MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx \n", basic.Fields.RevisionIdentifier);


	//Changing Revision Identifier
	*(UINT64*)alignedVirtualBuffer = basic.Fields.RevisionIdentifier;


	int status = __vmx_vmptrld(&alignedPhysicalBuffer);
	if (status)
	{
		DbgPrint("VMCS failed with status %d\n", status);
		return FALSE;
	}

	vmState->VMCS_REGION = alignedPhysicalBuffer;

	return TRUE;
}