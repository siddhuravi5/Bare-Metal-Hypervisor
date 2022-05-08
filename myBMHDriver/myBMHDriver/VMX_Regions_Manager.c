#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "Msr.h"
#include "Vmx.h"
#include "Helper.h"
#include "Global_Variables.h"
#include "Dpc.h"
#include "InlineAsm.h"
#include "BMHV_Routines.h"

/* Allocates Vmx regions for all logical cores (Vmxon region and Vmcs region) */
BOOLEAN Vmx_Dpc_Broadcast_Allocate_Vmxon_Regions(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{

	int CurrentProcessorNumber = KeGetCurrentProcessorNumber();

	LogInfo("Allocating Vmx Regions for logical core %d", CurrentProcessorNumber);

	// Enabling VMX Operation
	AsmEnableVmxOperation();

	LogInfo("VMX-Operation Enabled Successfully");

	if (!Vmx_Allocate_Vmxon_Region(&GuestState[CurrentProcessorNumber]))
	{
		LogError("Error in allocating memory for Vmxon region");
		return FALSE;
	}
	if (!Vmx_Allocate_Vmcs_Region(&GuestState[CurrentProcessorNumber]))
	{
		LogError("Error in allocating memory for Vmcs region");
		return FALSE;
	}

	// Wait for all DPCs to synchronize at this point
	KeSignalCallDpcSynchronize(SystemArgument2);

	// Mark the DPC as being complete
	KeSignalCallDpcDone(SystemArgument1);

	return TRUE;
}

/* Allocates Vmxon region and set the Revision ID based on IA32_VMX_BASIC_MSR */
BOOLEAN Vmx_Allocate_Vmxon_Region(VIRTUAL_MACHINE_STATE* CurrentGuestState)
{
	PHYSICAL_ADDRESS PhysicalMax = { 0 };
	IA32_VMX_BASIC_MSR VmxBasicMsr = { 0 };
	int VmxonSize;
	int VmxonStatus;
	BYTE* VmxonRegion;
	UINT64 VmxonRegionPhysicalAddr;
	UINT64 AlignedVmxonRegion;
	UINT64 AlignedVmxonRegionPhysicalAddr;


	// at IRQL > DISPATCH_LEVEL memory allocation routines don't work
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();

	PhysicalMax.QuadPart = MAXULONG64;

	VmxonSize = 2 * VMXON_SIZE;

	// Allocating a 4-KByte Contigous Memory region
	VmxonRegion = MmAllocateContiguousMemory(VmxonSize + ALIGNMENT_PAGE_SIZE, PhysicalMax);

	if (VmxonRegion == NULL) {
		LogError("Couldn't Allocate Buffer for VMXON Region.");
		return FALSE;
	}

	VmxonRegionPhysicalAddr = VirtualAddressToPhysicalAddress(VmxonRegion);

	// zero-out memory 
	RtlSecureZeroMemory(VmxonRegion, VmxonSize + ALIGNMENT_PAGE_SIZE);


	AlignedVmxonRegion = (BYTE*)((ULONG_PTR)(VmxonRegion + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
	LogInfo("VMXON Region Address : %llx", AlignedVmxonRegion);

	// 4 kb >= buffers are aligned, just a double check to ensure if it's aligned
	AlignedVmxonRegionPhysicalAddr = (BYTE*)((ULONG_PTR)(VmxonRegionPhysicalAddr + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
	LogInfo("VMXON Region Physical Address : %llx", AlignedVmxonRegionPhysicalAddr);

	// get IA32_VMX_BASIC_MSR RevisionId
	VmxBasicMsr.All = __readmsr(MSR_IA32_VMX_BASIC);
	LogInfo("Revision Identifier (MSR_IA32_VMX_BASIC - MSR 0x480) : 0x%x", VmxBasicMsr.Fields.RevisionIdentifier);

	//Changing Revision Identifier
	*(UINT64*)AlignedVmxonRegion = VmxBasicMsr.Fields.RevisionIdentifier;

	// Execute Vmxon instruction
	VmxonStatus = __vmx_on(&AlignedVmxonRegionPhysicalAddr);
	if (VmxonStatus)
	{
		LogError("Executing Vmxon instruction failed with status : %d", VmxonStatus);
		return FALSE;
	}

	CurrentGuestState->VmxonRegionPhysicalAddress = AlignedVmxonRegionPhysicalAddr;

	// We save the allocated buffer (not the aligned buffer) because we want to free it in vmx termination
	CurrentGuestState->VmxonRegionVirtualAddress = VmxonRegion;

	return TRUE;
}

/* Allocate Vmcs region and set the Revision ID based on IA32_VMX_BASIC_MSR */
BOOLEAN Vmx_Allocate_Vmcs_Region(VIRTUAL_MACHINE_STATE* CurrentGuestState)
{
	PHYSICAL_ADDRESS PhysicalMax = { 0 };
	int VmcsSize;
	BYTE* VmcsRegion;
	UINT64 VmcsPhysicalAddr;
	UINT64 AlignedVmcsRegion;
	UINT64 AlignedVmcsRegionPhysicalAddr;
	IA32_VMX_BASIC_MSR VmxBasicMsr = { 0 };


	// at IRQL > DISPATCH_LEVEL memory allocation routines don't work
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();

	PhysicalMax.QuadPart = MAXULONG64;

	VmcsSize = 2 * VMCS_SIZE;
	VmcsRegion = MmAllocateContiguousMemory(VmcsSize + ALIGNMENT_PAGE_SIZE, PhysicalMax);  // Allocating a 4-KByte Contigous Memory region

	if (VmcsRegion == NULL) {
		LogError("Couldn't Allocate Buffer for VMCS Region.");
		return FALSE;
	}
	RtlSecureZeroMemory(VmcsRegion, VmcsSize + ALIGNMENT_PAGE_SIZE);

	VmcsPhysicalAddr = VirtualAddressToPhysicalAddress(VmcsRegion);

	AlignedVmcsRegion = (BYTE*)((ULONG_PTR)(VmcsRegion + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
	LogInfo("VMCS Region Address : %llx", AlignedVmcsRegion);

	AlignedVmcsRegionPhysicalAddr = (BYTE*)((ULONG_PTR)(VmcsPhysicalAddr + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
	LogInfo("VMCS Region Physical Address : %llx", AlignedVmcsRegionPhysicalAddr);

	// get IA32_VMX_BASIC_MSR RevisionId
	VmxBasicMsr.All = __readmsr(MSR_IA32_VMX_BASIC);
	LogInfo("Revision Identifier (MSR_IA32_VMX_BASIC - MSR 0x480) : 0x%x", VmxBasicMsr.Fields.RevisionIdentifier);


	//Changing Revision Identifier
	*(UINT64*)AlignedVmcsRegion = VmxBasicMsr.Fields.RevisionIdentifier;

	CurrentGuestState->VmcsRegionPhysicalAddress = AlignedVmcsRegionPhysicalAddr;
	// We save the allocated buffer (not the aligned buffer) because we want to free it in vmx termination
	CurrentGuestState->VmcsRegionVirtualAddress = VmcsRegion;

	return TRUE;
}

/* Allocate VMM Stack */
BOOLEAN Vmx_Allocate_Vmm_Stack(INT ProcessorID)
{
	UINT64 VmmStack;

	// Allocate stack for the VM Exit Handler.
	VmmStack = ExAllocatePoolWithTag(NonPagedPool, VMM_STACK_SIZE, POOLTAG);
	GuestState[ProcessorID].VmmStack = VmmStack;

	if (GuestState[ProcessorID].VmmStack == NULL)
	{
		LogError("Insufficient memory in allocationg Vmm stack");
		return FALSE;
	}
	RtlZeroMemory(GuestState[ProcessorID].VmmStack, VMM_STACK_SIZE);

	LogInfo("Vmm Stack for logical processor : 0x%llx", GuestState[ProcessorID].VmmStack);

	return TRUE;
}

/* Allocate a buffer forr Msr Bitmap */
BOOLEAN Vmx_Allocate_MSR_Bitmap(INT ProcessorID)
{
	// Allocate memory for MSRBitMap
	GuestState[ProcessorID].MsrBitmapVirtualAddress = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);  // should be aligned

	if (GuestState[ProcessorID].MsrBitmapVirtualAddress == NULL)
	{
		LogError("Insufficient memory in allocationg Msr bitmaps");
		return FALSE;
	}
	RtlZeroMemory(GuestState[ProcessorID].MsrBitmapVirtualAddress, PAGE_SIZE);

	GuestState[ProcessorID].MsrBitmapPhysicalAddress = VirtualAddressToPhysicalAddress(GuestState[ProcessorID].MsrBitmapVirtualAddress);

	LogInfo("Msr Bitmap Virtual Address : 0x%llx", GuestState[ProcessorID].MsrBitmapVirtualAddress);
	LogInfo("Msr Bitmap Physical Address : 0x%llx", GuestState[ProcessorID].MsrBitmapPhysicalAddress);

	// (Uncomment if you want to break on RDMSR and WRMSR to a special MSR Register)

	
	if (!BMHV_Set_Msr_Bitmap(0xC0000082, ProcessorID, TRUE, TRUE))
	{
		LogWarning("Invalid parameters sent to the HvSetMsrBitmap function");
		return FALSE;
	}
	

	return TRUE;
}


/* Allocate a buffer forr Msr Bitmap */
BOOLEAN Vmx_Allocate_IO_Bitmap(INT ProcessorID)
{
	// Allocate memory for MSRBitMap
	GuestState[ProcessorID].IOBitmapVirtualAddressA = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);  // should be aligned

	if (GuestState[ProcessorID].IOBitmapVirtualAddressA == NULL)
	{
		LogError("Insufficient memory in allocationg Msr bitmaps");
		return FALSE;
	}
	RtlZeroMemory(GuestState[ProcessorID].IOBitmapVirtualAddressA, PAGE_SIZE);

	GuestState[ProcessorID].IOBitmapPhysicalAddressA = VirtualAddressToPhysicalAddress(GuestState[ProcessorID].IOBitmapVirtualAddressA);

	LogInfo("IO Bitmap A Virtual Address : 0x%llx", GuestState[ProcessorID].IOBitmapVirtualAddressA);
	LogInfo("IO Bitmap A Physical Address : 0x%llx", GuestState[ProcessorID].IOBitmapPhysicalAddressA);

	// (Uncomment if you want to break on RDMSR and WRMSR to a special MSR Register)


	GuestState[ProcessorID].IOBitmapVirtualAddressB = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);  // should be aligned

	if (GuestState[ProcessorID].IOBitmapVirtualAddressB == NULL)
	{
		LogError("Insufficient memory in allocationg Msr bitmaps");
		return FALSE;
	}
	RtlZeroMemory(GuestState[ProcessorID].IOBitmapVirtualAddressB, PAGE_SIZE);

	GuestState[ProcessorID].IOBitmapPhysicalAddressB = VirtualAddressToPhysicalAddress(GuestState[ProcessorID].IOBitmapVirtualAddressB);

	LogInfo("IO Bitmap B Virtual Address : 0x%llx", GuestState[ProcessorID].IOBitmapVirtualAddressB);
	LogInfo("IO Bitmap B Physical Address : 0x%llx", GuestState[ProcessorID].IOBitmapPhysicalAddressB);
	for (int i = 0; i < PAGE_SIZE; i++) {
	SetBit(GuestState[ProcessorID].IOBitmapVirtualAddressA, i, TRUE);
	}
	for (int i = PAGE_SIZE; i < 2 * PAGE_SIZE; i++) {
		SetBit(GuestState[ProcessorID].IOBitmapVirtualAddressB, i, TRUE);
	}
	SetBit(GuestState[ProcessorID].IOBitmapVirtualAddressA, 0x64, FALSE);
	return TRUE;
}