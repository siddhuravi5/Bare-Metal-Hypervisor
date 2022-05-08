//  This file describe the routines in Hypervisor
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Msr.h"
#include "Vmx.h"
#include "Helper.h"
#include "Global_Variables.h"
#include "BMHV_Routines.h"
#include "Invept_Instruction_Handler.h"
#include "InlineAsm.h"
#include "Vmcall_Handler.h"
#include "Dpc.h"
#include <wdf.h>

/* Initialize Vmx */
BOOLEAN BMHV_Initialize_VMX()
{

	int LogicalProcessorsCount;

	/*** Start Virtualizing Current System ***/

	// Initiating EPTP and VMX
	if (!Initialize_VMX())
	{
		// there was error somewhere in initializing
		return FALSE;
	}

	LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

	for (size_t ProcessorID = 0; ProcessorID < LogicalProcessorsCount; ProcessorID++)
	{
		/*** Launching VM for Test (in the all logical processor) ***/

		//Allocating VMM Stack
		if (!Vmx_Allocate_Vmm_Stack(ProcessorID))
		{
			// Some error in allocating Vmm Stack
			return FALSE;
		}

		// Allocating MSR Bit 
		if (!Vmx_Allocate_MSR_Bitmap(ProcessorID))
		{
			// Some error in allocating Msr Bitmaps
			return FALSE;
		}

		if (!Vmx_Allocate_IO_Bitmap(ProcessorID)) {
			DbgPrint("Couldn't Allocate IO Bitmap\n");
		}

		/*** This function is deprecated as we want to supporrt more than 32 processors. ***/
		// BroadcastToProcessors(ProcessorID, AsmVmxSaveState);
	}

	// Read Current the Cr3
	InitiateCr3 = __readcr3();

	// As we want to support more than 32 processor (64 logical-core) we let windows execute our routine for us
	KeGenericCallDpc(BMHV_Dpc_Broadcast_Initialize_Guest, 0x0);

	//  Check if everything is ok then return true otherwise false
	if (AsmVmxVmcall(VMCALL_TEST, 0x22, 0x333, 0x4444) == STATUS_SUCCESS)
	{
		DbgPrint("VMCall Test was successful\n");
		
		//read msr test
		__readmsr(0xC0000082);

		//cpuid test
		//read cpuid test
		INT32 cpu_info[4];
		DbgPrint("====================================================================================================\n");
		__cpuidex(cpu_info, 0x40000001, (INT32)1);

		if (cpu_info[0] == 'BMHV') {
			DbgPrint("CPU Info : %d\n", cpu_info[0]);
			DbgPrint("This number is the integer representation of the multi-character constant 'BMHV'\n");
			DbgPrint("[B]are [M]etal [H]yper [V]isor\n");
		}
		DbgPrint("====================================================================================================\n");
		///////////////// Test Hook after Vmx is launched /////////////////
		VMX_ROOT = FALSE;
		EptPageHook(ExAllocatePoolWithTag, TRUE);
		///////////////////////////////////////////////////////////////////
		DbgPrint("Hooked ExAllocatePoolWithTag function\n");
		DbgPrint("====================================================================================================\n");
		
		return TRUE;
	}
	else
	{
		DbgPrint("VMCall Test failed\n");
		return FALSE;
	}

}

/* Check whether VMX Feature is supported or not */
BOOLEAN BMHV_Check_Vmx_Support()
{
	CPUID Data = { 0 };
	IA32_FEATURE_CONTROL_MSR FeatureControlMsr = { 0 };

	// VMX bit
	__cpuid((int*)&Data, 1);
	if ((Data.ecx & (1 << 5)) == 0)
		return FALSE;

	FeatureControlMsr.All = __readmsr(MSR_IA32_FEATURE_CONTROL);

	// BIOS lock check
	if (FeatureControlMsr.Fields.Lock == 0)
	{
		FeatureControlMsr.Fields.Lock = TRUE;
		FeatureControlMsr.Fields.EnableVmxon = TRUE;
		__writemsr(MSR_IA32_FEATURE_CONTROL, FeatureControlMsr.All);
	}
	else if (FeatureControlMsr.Fields.EnableVmxon == FALSE)
	{
		LogError("Intel VMX feature is locked in BIOS");
		return FALSE;
	}

	return TRUE;
}

/* Returns the Cpu Based and Secondary Processor Based Controls and other controls based on hardware support */
ULONG BMHV_Adjust_Controls(ULONG Ctl, ULONG Msr)
{
	MSR MsrValue = { 0 };

	MsrValue.Content = __readmsr(Msr);
	Ctl &= MsrValue.High;     /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.Low;      /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}


/* Set guest's selector registers */
BOOLEAN BMHV_Set_Guest_Selector(PVOID GdtBase, ULONG SegmentRegister, USHORT Selector)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG AccessRights;

	BMHV_Get_Segment_Descriptor(&SegmentSelector, Selector, GdtBase);
	AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

	if (!Selector)
		AccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + SegmentRegister * 2, Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT + SegmentRegister * 2, SegmentSelector.LIMIT);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + SegmentRegister * 2, AccessRights);
	__vmx_vmwrite(GUEST_ES_BASE + SegmentRegister * 2, SegmentSelector.BASE);

	return TRUE;
}


/* Get Segment Descriptor */
BOOLEAN BMHV_Get_Segment_Descriptor(PSEGMENT_SELECTOR SegmentSelector, USHORT Selector, PUCHAR GdtBase)
{
	PSEGMENT_DESCRIPTOR SegDesc;

	if (!SegmentSelector)
		return FALSE;

	if (Selector & 0x4) {
		return FALSE;
	}

	SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

	SegmentSelector->SEL = Selector;
	SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
	SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
	SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

	if (!(SegDesc->ATTR0 & 0x10)) { // LA_ACCESSED
		ULONG64 tmp;
		// this is a TSS or callgate etc, save the base high part
		tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
		SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (tmp << 32);
	}

	if (SegmentSelector->ATTRIBUTES.Fields.G) {
		// 4096-bit granularity is enabled for this segment, scale the limit
		SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
	}

	return TRUE;
}


/* Handle Cpuid Vmexits*/
VOID BMHV_Handle_Cpuid_Call(PGUEST_REGS RegistersState)
{
	INT32 cpu_info[4];
	ULONG Mode = 0;


	// Check for the magic CPUID sequence, and check that it is coming from
	// Ring 0. Technically we could also check the RIP and see if this falls
	// in the expected function, but we may want to allow a separate "unload"
	// driver or code at some point.

	/***  It's better to turn off hypervisor from Vmcall ***/
	/*
	__vmx_vmread(GUEST_CS_SELECTOR, &Mode);
	Mode = Mode & RPL_MASK;
	if ((RegistersState->rax == 0x41414141) && (RegistersState->rcx == 0x42424242) && Mode == DPL_SYSTEM)
	{
		return TRUE; // Indicates we have to turn off VMX
	}
	*/

	// Otherwise, issue the CPUID to the logical processor based on the indexes
	// on the VP's GPRs.
	__cpuidex(cpu_info, (INT32)RegistersState->rax, (INT32)RegistersState->rcx);

	// Check if this was CPUID 1h, which is the features request.
	if (RegistersState->rax == 1)
	{

		// Set the Hypervisor Present-bit in RCX, which Intel and AMD have both
		// reserved for this indication.
		cpu_info[2] |= HYPERV_HYPERVISOR_PRESENT_BIT;
	}

	else if (RegistersState->rax == HYPERV_CPUID_INTERFACE)
	{
		// Return our interface identifier
		cpu_info[0] = 'BMHV'; // [H]yper[v]isor [F]rom [S]cratch 
	}

	// Copy the values from the logical processor registers into the VP GPRs.
	RegistersState->rax = cpu_info[0];
	RegistersState->rbx = cpu_info[1];
	RegistersState->rcx = cpu_info[2];
	RegistersState->rdx = cpu_info[3];

	DbgPrint("CPUID[0] : 0x%lx\n", cpu_info[0]);
	DbgPrint("CPUID[1] : 0x%lx\n", cpu_info[1]);
	DbgPrint("CPUID[2] : 0x%lx\n", cpu_info[2]);
	DbgPrint("CPUID[3] : 0x%lx\n", cpu_info[3]);
	PCHAR msgData = "";
	if (secretDataLength < 262) {
		for (int j = 0; j < 4; j++) {
			switch (j) {
			case 0: msgData = "CPUID[0] : 0x"; break;
			case 1: msgData = "CPUID[1] : 0x"; break;
			case 2: msgData = "CPUID[2] : 0x"; break;
			case 3: msgData = "CPUID[3] : 0x"; break;
			}
			
			//char buffer[20];
			//converting integer value to character buffer
			RtlZeroBytes(GlobalBuffer, 25);
			sprintf(GlobalBuffer, "%x", cpu_info[j]);
			for (int i = 0; i < strlen(msgData); i++) {
				SecretData[secretDataLength] = *(msgData + i);
				secretDataLength += 1;
			}
			for (int i = 0; i < 20 && *(GlobalBuffer + i) != '\0'; i++) {
				SecretData[secretDataLength] = *(GlobalBuffer + i);
				secretDataLength += 1;
			}
			SecretData[secretDataLength] = '\n';
			secretDataLength += 1;
		}
		SecretData[secretDataLength] = '\n';
		secretDataLength += 1;
		
	}

}

/* Handles Guest Access to control registers */
VOID BMHV_Handle_Control_Register_Access(PGUEST_REGS GuestState)
{
	ULONG ExitQualification = 0;
	PMOV_CR_QUALIFICATION CrExitQualification;
	PULONG64 RegPtr;
	INT64 GuestRsp = 0;

	__vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);

	CrExitQualification = (PMOV_CR_QUALIFICATION)&ExitQualification;

	RegPtr = (PULONG64)&GuestState->rax + CrExitQualification->Fields.Register;
	//DbgPrint("Registe number : 0x%lx\n", CrExitQualification->Fields.Register);

	/* Because its RSP and as we didn't save RSP correctly (because of pushes) so we have make it points to the GUEST_RSP */
	if (CrExitQualification->Fields.Register == 4)
	{
		DbgPrint("SP req\n");
		__vmx_vmread(GUEST_RSP, &GuestRsp);
		*RegPtr = GuestRsp;
	}

	switch (CrExitQualification->Fields.AccessType)
	{
	case TYPE_MOV_TO_CR:
	{
		switch (CrExitQualification->Fields.ControlRegister)
		{
		case 0:
			__vmx_vmwrite(GUEST_CR0, *RegPtr);
			__vmx_vmwrite(CR0_READ_SHADOW, *RegPtr);
			break;
		case 3:

			//__vmx_vmwrite(GUEST_CR3, (*RegPtr & ~(1ULL << 63)));
			
			//DbgPrint("act value : 0x%llx\n", (*RegPtr & ~(1ULL << 63)));
			switch (CrExitQualification->Fields.Register)
			{

			case 0:  __vmx_vmwrite(GUEST_CR3, GuestState->rax);/* DbgPrint("our value : 0x%llx\n", GuestState->rax);*/ break;
			case 1:  __vmx_vmwrite(GUEST_CR3, GuestState->rcx);/* DbgPrint("our value : 0x%llx\n", GuestState->rcx);*/ break;
			case 2:  __vmx_vmwrite(GUEST_CR3, GuestState->rdx);/* DbgPrint("our value : 0x%llx\n", GuestState->rdx);*/ break;
			case 3:  __vmx_vmwrite(GUEST_CR3, GuestState->rbx);/* DbgPrint("our value : 0x%llx\n", GuestState->rbx);*/ break;
			case 4:  __vmx_vmwrite(GUEST_CR3, GuestState->rsp);/* DbgPrint("our value : 0x%llx\n", GuestState->rsp);*/ break;
			case 5:  __vmx_vmwrite(GUEST_CR3, GuestState->rbp);/* DbgPrint("our value : 0x%llx\n", GuestState->rbp);*/ break;
			case 6:  __vmx_vmwrite(GUEST_CR3, GuestState->rsi);/* DbgPrint("our value : 0x%llx\n", GuestState->rsi);*/ break;
			case 7:  __vmx_vmwrite(GUEST_CR3, GuestState->rdi);/* DbgPrint("our value : 0x%llx\n", GuestState->rdi);*/ break;
			}
			if (CrExitQualification->Fields.ControlRegister == 4) {
				__vmx_vmwrite(GUEST_CR3, (*RegPtr & ~(1ULL << 63)));
			}

			break;
		case 4:
			__vmx_vmwrite(GUEST_CR4, *RegPtr);
			__vmx_vmwrite(CR4_READ_SHADOW, *RegPtr);
			break;
		default:
			LogWarning("Unsupported register %d in handling control registers access", CrExitQualification->Fields.ControlRegister);
			break;
		}
	}
	break;

	case TYPE_MOV_FROM_CR:
	{
		switch (CrExitQualification->Fields.ControlRegister)
		{
		case 0:
			__vmx_vmread(GUEST_CR0, RegPtr);
			break;
		case 3:
			__vmx_vmread(GUEST_CR3, RegPtr);
			break;
		case 4:
			__vmx_vmread(GUEST_CR4, RegPtr);
			break;
		default:
			LogWarning("Unsupported register %d in handling control registers access", CrExitQualification->Fields.ControlRegister);
			break;
		}
	}
	break;

	default:
		LogWarning("Unsupported operation %d in handling control registers access", CrExitQualification->Fields.AccessType);
		break;
	}

}

/* Fill the guest's selector data */
VOID BMHV_Fill_Guest_Selector_Data(PVOID GdtBase, ULONG SegmentRegister, USHORT Selector)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG AccessRights;

	BMHV_Get_Segment_Descriptor(&SegmentSelector, Selector, GdtBase);
	AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

	if (!Selector)
		AccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + SegmentRegister * 2, Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT + SegmentRegister * 2, SegmentSelector.LIMIT);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + SegmentRegister * 2, AccessRights);
	__vmx_vmwrite(GUEST_ES_BASE + SegmentRegister * 2, SegmentSelector.BASE);

}

/* Handles in the cases when RDMSR causes a Vmexit*/
VOID BMHV_Handle_Msr_Read(PGUEST_REGS GuestRegs)
{
	MSR msr = { 0 };


	// RDMSR. The RDMSR instruction causes a VM exit if any of the following are true:
	// 
	// The "use MSR bitmaps" VM-execution control is 0.
	// The value of ECX is not in the ranges 00000000H - 00001FFFH and C0000000H - C0001FFFH
	// The value of ECX is in the range 00000000H - 00001FFFH and bit n in read bitmap for low MSRs is 1,
	//   where n is the value of ECX.
	// The value of ECX is in the range C0000000H - C0001FFFH and bit n in read bitmap for high MSRs is 1,
	//   where n is the value of ECX & 00001FFFH.

	
	if (((GuestRegs->rcx <= 0x00001FFF)) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
	{
	
	msr.Content = __readmsr(GuestRegs->rcx);
	DbgPrint("====================================================================================================\n");
	DbgPrint("Read Msr : 0x%llx\n", GuestRegs->rcx);
	DbgPrint("MSR Value : 0x%llx\n", msr.Content);
	DbgPrint("====================================================================================================\n");
	AddToSecretData("Read Msr : 0x", GuestRegs->rcx);
	AddToSecretData("MSR Value : 0x", msr.Content);
	}
	else
	{
		msr.Content = 0;
	}
	

	GuestRegs->rax = msr.Low;
	GuestRegs->rdx = msr.High;
	//DbgPrint("Read MSR 0x%llx, Value = 0x%llx\n", GuestRegs->rcx, msr.Content);
}

/* Handles in the cases when WRMSR causes a Vmexit*/
VOID BMHV_Handle_Msr_Write(PGUEST_REGS GuestRegs)
{
	MSR msr = { 0 };

	// Check for sanity of MSR 
	/*
	if ((GuestRegs->rcx <= 0x00001FFF) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
	{
	*/
	msr.Low = (ULONG)GuestRegs->rax;
	msr.High = (ULONG)GuestRegs->rdx;
	__writemsr(GuestRegs->rcx, msr.Content);
	/* } */

}

/* Set bits in Msr Bitmap */
BOOLEAN BMHV_Set_Msr_Bitmap(ULONG64 Msr, INT ProcessorID, BOOLEAN ReadDetection, BOOLEAN WriteDetection)
{

	if (!ReadDetection && !WriteDetection)
	{
		// Invalid Command
		return FALSE;
	}

	if (Msr <= 0x00001FFF)
	{
		if (ReadDetection)
		{
			SetBit(GuestState[ProcessorID].MsrBitmapVirtualAddress, Msr, TRUE);
		}
		if (WriteDetection)
		{
			SetBit(GuestState[ProcessorID].MsrBitmapVirtualAddress + 2048, Msr, TRUE);
		}
	}
	else if ((Msr >= 0xC0000000 ) && (Msr <= 0xC0001FFF))
	{
		if (ReadDetection)
		{
			//DbgPrint("addr : 0x%llx, sum : 0x%llx\n", GuestState[ProcessorID].MsrBitmapVirtualAddress, GuestState[ProcessorID].MsrBitmapVirtualAddress + 1024*8);
			SetBit(GuestState[ProcessorID].MsrBitmapVirtualAddress + 1024, Msr - 0xC0000000, TRUE);
		}
		if (WriteDetection)
		{
			SetBit(GuestState[ProcessorID].MsrBitmapVirtualAddress + 3072, Msr - 0xC0000000, TRUE);

		}
	}
	else
	{
		return FALSE;
	}
	return TRUE;
}

/* Add the current instruction length to guest rip to resume to next instruction */
VOID BMHV_Resume_To_Next_Instruction()
{
	ULONG64 ResumeRIP = NULL;
	ULONG64 CurrentRIP = NULL;
	ULONG ExitInstructionLength = 0;

	__vmx_vmread(GUEST_RIP, &CurrentRIP);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

	ResumeRIP = CurrentRIP + ExitInstructionLength;

	__vmx_vmwrite(GUEST_RIP, ResumeRIP);
}

/* Notify all core to invalidate their EPT */
VOID BMHV_Notify_All_To_Invalidate_Ept()
{
	// Let's notify them all
	KeIpiGenericCall(BMHV_Invalidate_Ept_By_Vmcall, EptState->EptPointer.Flags);
}

/* Invalidate EPT using Vmcall (should be called from Vmx non root mode) */
VOID BMHV_Invalidate_Ept_By_Vmcall(UINT64 Context)
{
	if (Context == NULL)
	{
		// We have to invalidate all contexts
		AsmVmxVmcall(VMCALL_INVEPT_ALL_CONTEXT, NULL, NULL, NULL);
	}
	else
	{
		// We have to invalidate all contexts
		AsmVmxVmcall(VMCALL_INVEPT_SINGLE_CONTEXT, Context, NULL, NULL);
	}
}


/* Returns the stack pointer, to change in the case of Vmxoff */
UINT64 BMHV_Return_Stack_Pointer_For_Vmxoff()
{
	return GuestState[KeGetCurrentProcessorNumber()].VmxoffState.GuestRsp;
}

/* Returns the instruction pointer, to change in the case of Vmxoff */
UINT64 BMHV_Return_Instruction_Pointer_For_Vmxoff()
{
	return GuestState[KeGetCurrentProcessorNumber()].VmxoffState.GuestRip;
}


/* The broadcast function which initialize the guest. */
VOID BMHV_Dpc_Broadcast_Initialize_Guest(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	// Save the vmx state and prepare vmcs setup and finally execute vmlaunch instruction
	AsmVmxSaveState();

	// Wait for all DPCs to synchronize at this point
	KeSignalCallDpcSynchronize(SystemArgument2);

	// Mark the DPC as being complete
	KeSignalCallDpcDone(SystemArgument1);
}

/* Terminate Vmx on all logical cores. */
VOID BMHV_Terminate_Vmx()
{
	// Broadcast to terminate Vmx
	KeGenericCallDpc(BMHV_Dpc_Broadcast_Terminate_Guest, 0x0);

	/* De-allocatee global variables */

	// Free each split 
	FOR_EACH_LIST_ENTRY(EptState->EptPageTable, DynamicSplitList, VMM_EPT_DYNAMIC_SPLIT, Split)
		ExFreePoolWithTag(Split, POOLTAG);
	FOR_EACH_LIST_ENTRY_END();

	// Free Identity Page Table
	MmFreeContiguousMemory(EptState->EptPageTable);

	// Free GuestState
	ExFreePoolWithTag(GuestState, POOLTAG);

	// Free EptState
	ExFreePoolWithTag(EptState, POOLTAG);

}

/* The broadcast function which terminate the guest. */
VOID BMHV_Dpc_Broadcast_Terminate_Guest(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	// Terminate Vmx using Vmcall
	if (!Terminate_VMX())
	{
		LogError("There were an error terminating Vmx");
	}

	// Wait for all DPCs to synchronize at this point
	KeSignalCallDpcSynchronize(SystemArgument2);

	// Mark the DPC as being complete
	KeSignalCallDpcDone(SystemArgument1);
}
VOID BMHV_Set_Monitor_Trap_Flag(BOOLEAN Set)
{
	ULONG CpuBasedVmExecControls = 0;

	// Read the previous flag
	__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, &CpuBasedVmExecControls);

	if (Set) {
		CpuBasedVmExecControls |= CPU_BASED_MONITOR_TRAP_FLAG;
		DbgPrint("Set the Montor Trap Flag\n");
	}
	else {
		CpuBasedVmExecControls &= ~CPU_BASED_MONITOR_TRAP_FLAG;
		DbgPrint("Unset the Montor Trap Flag\n");
	}

	// Set the new value 
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, CpuBasedVmExecControls);
}


int digitCount(int N) {
	int m = N;
	int digit = 0;
	while (m) {

		// Increment number of digits
		digit++;

		// Truncate the last
		// digit from the number
		m /= 10;
	}
	return digit;
}
void AddToSecretData(PCHAR msgData,int num) {
		//PCHAR msgData = msg;
		//char buffer[20];
		if (secretDataLength > 450) return;
	    RtlZeroBytes(GlobalBuffer, 25);

		if (msgData != NULL) {
			for (int i = 0; i < strlen(msgData); i++) {
				SecretData[secretDataLength] = *(msgData + i);
				secretDataLength += 1;
			}
		}
		if (secretDataLength > 450) return;

		if (num != -1) {
			sprintf(GlobalBuffer, "%x", num);
			for (int i = 0; i < 20 && *(GlobalBuffer + i) != '\0'; i++) {
				SecretData[secretDataLength] = *(GlobalBuffer + i);
				secretDataLength += 1;
			}
			if (*(GlobalBuffer) == '\0') {
				SecretData[secretDataLength] = '0';
				secretDataLength += 1;
			}
		}
		
		SecretData[secretDataLength] = '\n';
		secretDataLength += 1;
}