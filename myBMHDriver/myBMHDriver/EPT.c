#include <ntddk.h>
#include "VMX.h"
#include "EPT.h"

//this variable points to our guest code
UINT64 VirtualGuestMemoryAddress;	//defined globally

PEPTP EPTP_Initialize()
{
	PAGED_CODE();

	// Allocate EPTP
	PEPTP ExtendedPageTablePointer = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

	if (!ExtendedPageTablePointer) {
		return NULL;
	}
	//zero out the allocated memory
	RtlZeroMemory(ExtendedPageTablePointer, PAGE_SIZE);

	//	Allocate EPT PML4
	PEPT_PML4E ExtendedPageTable_PML4 = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
	if (!ExtendedPageTable_PML4) {
		ExFreePoolWithTag(ExtendedPageTablePointer, POOLTAG);
		return NULL;
	}
	RtlZeroMemory(ExtendedPageTable_PML4, PAGE_SIZE);

	//	Allocate EPT Page-Directory-Pointer-Table
	PEPT_PDPTE ExtendedPageTable_PDPT = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
	if (!ExtendedPageTable_PDPT) {
		ExFreePoolWithTag(ExtendedPageTable_PML4, POOLTAG);
		ExFreePoolWithTag(ExtendedPageTablePointer, POOLTAG);
		return NULL;
	}
	RtlZeroMemory(ExtendedPageTable_PDPT, PAGE_SIZE);

	//	Allocate EPT Page-Directory
	PEPT_PDE ExtendedPageTable_PD = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

	if (!ExtendedPageTable_PD) {
		ExFreePoolWithTag(ExtendedPageTable_PDPT, POOLTAG);
		ExFreePoolWithTag(ExtendedPageTable_PML4, POOLTAG);
		ExFreePoolWithTag(ExtendedPageTablePointer, POOLTAG);
		return NULL;
	}
	RtlZeroMemory(ExtendedPageTable_PD, PAGE_SIZE);

	//	Allocate EPT Page-Table
	PEPT_PTE ExtendedPageTable_PT = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

	if (!ExtendedPageTable_PT) {
		ExFreePoolWithTag(ExtendedPageTable_PD, POOLTAG);
		ExFreePoolWithTag(ExtendedPageTable_PDPT, POOLTAG);
		ExFreePoolWithTag(ExtendedPageTable_PML4, POOLTAG);
		ExFreePoolWithTag(ExtendedPageTablePointer, POOLTAG);
		return NULL;
	}
	RtlZeroMemory(ExtendedPageTable_PT, PAGE_SIZE);

	// Setup PT by allocating two pages Continuously
	// We allocate two pages because we need 1 page for our RIP to start and 1 page for RSP 1 + 1 = 2

	const int PagesToAllocate = 10;
	UINT64* Memory_For_Guest_Code = (UINT64*)ExAllocatePoolWithTag(NonPagedPool, PagesToAllocate * PAGE_SIZE, POOLTAG);

	//this guest memory is our virtual machine, and guest IP in VMCS points to this address
	VirtualGuestMemoryAddress = (UINT64)Memory_For_Guest_Code;

	RtlZeroMemory((PVOID)Memory_For_Guest_Code, PagesToAllocate * PAGE_SIZE);

	for (size_t i = 0; i < PagesToAllocate; i++)
	{
		ExtendedPageTable_PT[i].Fields.AccessedFlag = 0;

		ExtendedPageTable_PT[i].Fields.DirtyFlag = 0;
		ExtendedPageTable_PT[i].Fields.EPTMemoryType = 6;
		ExtendedPageTable_PT[i].Fields.Execute = 1;
		ExtendedPageTable_PT[i].Fields.ExecuteForUserMode = 0;
		ExtendedPageTable_PT[i].Fields.IgnorePAT = 0;
		ExtendedPageTable_PT[i].Fields.PhysicalAddress = (VirtualAddress_to_PhysicalAddress(Memory_For_Guest_Code + (i * PAGE_SIZE)) / PAGE_SIZE);
		ExtendedPageTable_PT[i].Fields.Read = 1;
		ExtendedPageTable_PT[i].Fields.SuppressVE = 0;
		ExtendedPageTable_PT[i].Fields.Write = 1;

	}

	// Setting up PDE
	ExtendedPageTable_PD->Fields.Accessed = 0;
	ExtendedPageTable_PD->Fields.Execute = 1;
	ExtendedPageTable_PD->Fields.ExecuteForUserMode = 0;
	ExtendedPageTable_PD->Fields.Ignored1 = 0;
	ExtendedPageTable_PD->Fields.Ignored2 = 0;
	ExtendedPageTable_PD->Fields.Ignored3 = 0;
	ExtendedPageTable_PD->Fields.PhysicalAddress = (VirtualAddress_to_PhysicalAddress(ExtendedPageTable_PT) / PAGE_SIZE);
	ExtendedPageTable_PD->Fields.Read = 1;
	ExtendedPageTable_PD->Fields.Reserved1 = 0;
	ExtendedPageTable_PD->Fields.Reserved2 = 0;
	ExtendedPageTable_PD->Fields.Write = 1;

	// Setting up PDPTE
	ExtendedPageTable_PDPT->Fields.Accessed = 0;
	ExtendedPageTable_PDPT->Fields.Execute = 1;
	ExtendedPageTable_PDPT->Fields.ExecuteForUserMode = 0;
	ExtendedPageTable_PDPT->Fields.Ignored1 = 0;
	ExtendedPageTable_PDPT->Fields.Ignored2 = 0;
	ExtendedPageTable_PDPT->Fields.Ignored3 = 0;
	ExtendedPageTable_PDPT->Fields.PhysicalAddress = (VirtualAddress_to_PhysicalAddress(ExtendedPageTable_PD) / PAGE_SIZE);
	ExtendedPageTable_PDPT->Fields.Read = 1;
	ExtendedPageTable_PDPT->Fields.Reserved1 = 0;
	ExtendedPageTable_PDPT->Fields.Reserved2 = 0;
	ExtendedPageTable_PDPT->Fields.Write = 1;

	// Setting up PML4E
	ExtendedPageTable_PML4->Fields.Accessed = 0;
	ExtendedPageTable_PML4->Fields.Execute = 1;
	ExtendedPageTable_PML4->Fields.ExecuteForUserMode = 0;
	ExtendedPageTable_PML4->Fields.Ignored1 = 0;
	ExtendedPageTable_PML4->Fields.Ignored2 = 0;
	ExtendedPageTable_PML4->Fields.Ignored3 = 0;
	ExtendedPageTable_PML4->Fields.PhysicalAddress = (VirtualAddress_to_PhysicalAddress(ExtendedPageTable_PDPT) / PAGE_SIZE);
	ExtendedPageTable_PML4->Fields.Read = 1;
	ExtendedPageTable_PML4->Fields.Reserved1 = 0;
	ExtendedPageTable_PML4->Fields.Reserved2 = 0;
	ExtendedPageTable_PML4->Fields.Write = 1;

	// Setting up EPTP
	ExtendedPageTablePointer->Fields.DirtyAndAceessEnabled = 1;
	ExtendedPageTablePointer->Fields.MemoryType = 6; // 6 = Write-back (WB)
	ExtendedPageTablePointer->Fields.PageWalkLength = 3;  // 4 (tables walked) - 1 = 3 
	ExtendedPageTablePointer->Fields.PML4Address = (VirtualAddress_to_PhysicalAddress(ExtendedPageTable_PML4) / PAGE_SIZE);
	ExtendedPageTablePointer->Fields.Reserved1 = 0;
	ExtendedPageTablePointer->Fields.Reserved2 = 0;

	DbgPrint("Extended Page Table Pointer is allocated at %llx", ExtendedPageTablePointer);

	return ExtendedPageTablePointer;

}

/*
unsigned char INVEPT(UINT32 type, INVEPT_DESC* descriptor)
{
	if (!descriptor)
	{
		static INVEPT_DESC zero_descriptor = { 0 };
		descriptor = &zero_descriptor;
	}

	return INVEPT_Instruction(type, descriptor);
}

unsigned char INVEPT_ALL_CONTEXTS()
{
	return INVEPT(all_contexts, NULL);
}

unsigned char INVEPT_SINGLE_CONTEXT(EPTP ept_pointer)
{
	INVEPT_DESC descriptor = { ept_pointer, 0 };
	return INVEPT(single_context, &descriptor);
}
*/