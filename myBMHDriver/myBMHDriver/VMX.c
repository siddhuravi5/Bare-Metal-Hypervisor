#include "Msr.h"
#include "Vmx.h"
#include "Helper.h"
#include "Ept.h"
#include "InlineAsm.h"
#include "Global_Variables.h"
#include "Vmcall_Handler.h"
#include "BMHV_Routines.h"
#include "Dpc.h"
#include "wchar.h"
#include "NMI_Interrupts.h"

BOOLEAN Initialize_VMX()
{
	int ProcessorCount;
	KAFFINITY AffinityMask;

	//Checks support for Hardware Virtualization
	if (!BMHV_Check_Vmx_Support())
	{
		LogError("VMX is not supported in this machine !");
		return FALSE;
	}

	PAGED_CODE();

	ProcessorCount = KeQueryActiveProcessorCount(0);

	// Allocate global variable to hold Guest(s) state
	GuestState = ExAllocatePoolWithTag(NonPagedPool, sizeof(VIRTUAL_MACHINE_STATE) * ProcessorCount, POOLTAG);

	if (!GuestState)
	{
		LogError("Insufficient memory");
		return FALSE;
	}

	// Zero memory
	RtlZeroMemory(GuestState, sizeof(VIRTUAL_MACHINE_STATE) * ProcessorCount);

	// Allocate	global variable to hold Ept State
	// it holds all the ept tables
	EptState = ExAllocatePoolWithTag(NonPagedPool, sizeof(EPT_STATE), POOLTAG);

	if (!EptState)
	{
		LogError("Insufficient memory");
		return FALSE;
	}

	// Zero memory
	RtlZeroMemory(EptState, sizeof(EPT_STATE));

	// Check whether EPT is supported or not
	if (!EptCheckFeatures())
	{
		LogError("Your processor doesn't support all EPT features");
		return FALSE;
	}
	else
	{
		// Our processor supports EPT, now let's build MTRR
		LogInfo("Your processor supports all EPT features");

		// Build MTRR Map
		if (!EptBuildMtrrMap())
		{
			LogError("Could not build Mtrr memory map");
			return FALSE;
		}
		LogInfo("Mtrr memory map built successfully");
	}

	if (!EptLogicalProcessorInitialize())
	{
		// There were some errors in EptLogicalProcessorInitialize
		return FALSE;
	}

	// Allocate and run Vmxon and Vmptrld on all logical cores
	KeGenericCallDpc(Vmx_Dpc_Broadcast_Allocate_Vmxon_Regions, 0x0);

	// Everything is ok, let's return true
	return TRUE;
}

/* Broadcast to terminate VMX on all logical cores */
BOOLEAN Terminate_VMX()
{
	int CurrentCoreIndex;
	NTSTATUS Status;

	// Get the current core index
	CurrentCoreIndex = KeGetCurrentProcessorNumber();

	LogInfo("\tTerminating VMX on logical core %d", CurrentCoreIndex);

	// Execute Vmcall to to turn off vmx from Vmx root mode
	Status = AsmVmxVmcall(VMCALL_VMXOFF, NULL, NULL, NULL);

	// Free the destination memory
	MmFreeContiguousMemory(GuestState[CurrentCoreIndex].VmxonRegionVirtualAddress);
	MmFreeContiguousMemory(GuestState[CurrentCoreIndex].VmcsRegionVirtualAddress);
	ExFreePoolWithTag(GuestState[CurrentCoreIndex].VmmStack, POOLTAG);
	ExFreePoolWithTag(GuestState[CurrentCoreIndex].MsrBitmapVirtualAddress, POOLTAG);

	if (Status == STATUS_SUCCESS)
	{
		return TRUE;
	}

	return FALSE;
}

BOOLEAN Vmx_Virtualize_Current_System(PVOID GuestStack) {

	ULONG64 ErrorCode;
	INT ProcessorID;

	ProcessorID = KeGetCurrentProcessorNumber();

	Log("======================== Virtualizing Current System (Logical Core : 0x%x) ========================", ProcessorID);

	// Clear the VMCS State
	if (!Vmx_Clear_Vmcs_State(&GuestState[ProcessorID])) {
		LogError("Failed to clear vmcs");
		return FALSE;
	}

	// Load VMCS (Set the Current VMCS)
	if (!Vmx_Load_Vmcs(&GuestState[ProcessorID]))
	{
		LogError("Failed to load vmcs");
		return FALSE;
	}

	LogInfo("Setting up VMCS for current logical core");
	Vmx_Setup_Vmcs(&GuestState[ProcessorID], GuestStack);

	LogInfo("Executing VMLAUNCH on logical core %d", ProcessorID);

	__vmx_vmlaunch();

	/* if Vmlaunch succeed will never be here ! */

	// Execute Vmxoff
	__vmx_off();

	ErrorCode = 0;
	__vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
	LogError("VMLAUNCH Error : 0x%llx", ErrorCode);

	LogWarning("VMXOFF Executed Successfully");

	DbgBreakPoint();
	return FALSE;
}

/*To make the selected VMCS Active and Current*/
VOID Vmx_Vmptrst()
{
	PHYSICAL_ADDRESS VmcsPhysicalAddr;
	VmcsPhysicalAddr.QuadPart = 0;
	__vmx_vmptrst((unsigned __int64*)&VmcsPhysicalAddr);

	LogInfo("Vmptrst result : %llx", VmcsPhysicalAddr);
}


/*Clears the VMCS, and makes the current VMCS Inactive*/
BOOLEAN Vmx_Clear_Vmcs_State(VIRTUAL_MACHINE_STATE* CurrentGuestState)
{
	int VmclearStatus;

	// Clear the state of the VMCS to inactive
	VmclearStatus = __vmx_vmclear(&CurrentGuestState->VmcsRegionPhysicalAddress);

	LogInfo("Vmcs Vmclear Status : %d", VmclearStatus);

	if (VmclearStatus)
	{
		// Otherwise terminate the VMX
		LogWarning("VMCS failed to clear ( status : %d )", VmclearStatus);
		__vmx_off();
		return FALSE;
	}
	return TRUE;
}

/*Loads the selected VMCS*/
BOOLEAN Vmx_Load_Vmcs(VIRTUAL_MACHINE_STATE* CurrentGuestState) {

	int VmptrldStatus;

	VmptrldStatus = __vmx_vmptrld(&CurrentGuestState->VmcsRegionPhysicalAddress);
	if (VmptrldStatus)
	{
		LogWarning("VMCS failed to load ( status : %d )", VmptrldStatus);
		return FALSE;
	}
	return TRUE;
}
/*
//debug test - fixed now

BOOLEAN Setup_VMCS_Attempt(IN VIRTUAL_MACHINE_STATE* vmState, IN PEPTP EPTP) {
	//this function is not required

	BOOLEAN Status = FALSE;
	ULONG64 GdtBase = 0;
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	// Initialize VMCS Guest State Area.
	if (__vmx_vmwrite(GUEST_CR0, __readcr0()) ||
		__vmx_vmwrite(GUEST_CR3, __readcr3()) ||
		__vmx_vmwrite(GUEST_CR4, __readcr4()) ||
		__vmx_vmwrite(GUEST_DR7, __readdr(7)) ||
		__vmx_vmwrite(GUEST_RSP, 0) ||
		__vmx_vmwrite(GUEST_RIP, (ULONG64)VirtualGuestMemoryAddress) ||
		__vmx_vmwrite(GUEST_RFLAGS, Get_RFLAGS()) ||
		__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL)) ||
		__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS)) ||
		__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP)) ||
		__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP)) ||
		__vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL) ||
		__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE)) ||
		__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE))
		) {
		DbgPrint("Failed to set guest state. (__vmx_vmwrite failed).\n");
		return Status;
	}
	if (__vmx_vmwrite(CR0_READ_SHADOW, __readcr0()) ||
		__vmx_vmwrite(CR4_READ_SHADOW, __readcr4())
		) {
		DbgPrint("Failed to set cr0_read_shadow or cr4_read_shadow. (__vmx_vmwrite failed).\n");
		return Status;
	}
	/*__vmx_vmwrite(VM_ENTRY_CONTROLS, __readmsr(MSR_IA32_VMX_ENTRY_CTLS) |
		VM_ENTRY_IA32E_MODE);
	__vmx_vmwrite(VM_EXIT_CONTROLS, __readmsr(MSR_IA32_VMX_EXIT_CTLS) |
		VM_EXIT_HOST_ADDR_SPACE_SIZE);

	__vmx_vmwrite(EXCEPTION_BITMAP, 0);

	__int64 procbased_control0 = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
	__int64 procbased_control1 = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS) >> 32;
	__int64 procbased_control_final = (procbased_control0 & procbased_control1);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, procbased_control_final);

	__int64 pinbased_control0 = __readmsr(MSR_IA32_VMX_PINBASED_CTLS);
	__int64 pinbased_control1 = __readmsr(MSR_IA32_VMX_PINBASED_CTLS) >> 32;
	__int64 pinbased_control_final = (pinbased_control0 & pinbased_control1);
	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pinbased_control_final);

	//missed secondary processor

	union __vmx_entry_control_t entry_controls = { 0 };
	entry_controls.bits.ia32e_mode_guest = 1;
	vmx_adjust_entry_controls(&entry_controls);
	__vmx_vmwrite(VM_ENTRY_CONTROLS, entry_controls.control);

	union __vmx_exit_control_t exit_controls = { 0 };
	exit_controls.bits.host_address_space_size = 1;
	vmx_adjust_exit_controls(&exit_controls);
	__vmx_vmwrite(VM_EXIT_CONTROLS, exit_controls.control);

	union __vmx_pinbased_control_msr_t pinbased_controls = { 0 };
	vmx_adjust_pinbased_controls(&pinbased_controls);
	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pinbased_controls.control);

	/*union __vmx_primary_processor_based_control_t primary_controls = {0};
	primary_controls.bits.use_msr_bitmaps = 1;
	primary_controls.bits.active_secondary_controls = 1;
	vmx_adjust_primary_processor_based_controls(&primary_controls);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, primary_controls.control);

	union __vmx_secondary_processor_based_control_t secondary_controls = { 0 };
	secondary_controls.bits.enable_rdtscp = 1;
	secondary_controls.bits.enable_xsave_xrstor = 1;
	secondary_controls.bits.enable_invpcid = 1;
	vmx_adjust_secondary_processor_based_controls(&secondary_controls);
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, secondary_controls.control);

	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, HvAdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_ACTIVATE_MSR_BITMAP, MSR_IA32_VMX_PROCBASED_CTLS));
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, HvAdjustControls(CPU_BASED_CTL2_RDTSCP /* | CPU_BASED_CTL2_ENABLE_EPT, MSR_IA32_VMX_PROCBASED_CTLS2));

	
	__vmx_vmwrite(GUEST_CS_SELECTOR, GetCs());
	__vmx_vmwrite(GUEST_SS_SELECTOR, GetSs());
	__vmx_vmwrite(GUEST_DS_SELECTOR, GetDs());
	__vmx_vmwrite(GUEST_ES_SELECTOR, GetEs());
	__vmx_vmwrite(GUEST_FS_SELECTOR, GetFs());
	__vmx_vmwrite(GUEST_GS_SELECTOR, GetGs());
	__vmx_vmwrite(GUEST_LDTR_SELECTOR, GetLdtr());
	__vmx_vmwrite(GUEST_TR_SELECTOR, GetTr());

	__vmx_vmwrite(GUEST_CS_LIMIT, __segmentlimit(GetCs()));
	__vmx_vmwrite(GUEST_SS_LIMIT, __segmentlimit(GetSs()));
	__vmx_vmwrite(GUEST_DS_LIMIT, __segmentlimit(GetDs()));
	__vmx_vmwrite(GUEST_ES_LIMIT, __segmentlimit(GetEs()));
	__vmx_vmwrite(GUEST_FS_LIMIT, __segmentlimit(GetFs()));
	__vmx_vmwrite(GUEST_GS_LIMIT, __segmentlimit(GetGs()));
	__vmx_vmwrite(GUEST_LDTR_LIMIT, __segmentlimit(GetLdtr()));
	__vmx_vmwrite(GUEST_TR_LIMIT, __segmentlimit(GetTr()));

	struct __pseudo_descriptor_64_t gdtr;
	struct __pseudo_descriptor_64_t idtr;
	_sgdt(&gdtr);
	__sidt(&idtr);
	__vmx_vmwrite(GUEST_GDTR_BASE, gdtr.base_address);
	__vmx_vmwrite(GUEST_GDTR_LIMIT, gdtr.limit);
	__vmx_vmwrite(GUEST_IDTR_BASE, idtr.base_address);
	__vmx_vmwrite(GUEST_IDTR_LIMIT, idtr.limit);

	__vmx_vmwrite(GUEST_CS_BASE, get_segment_base(gdtr.base_address, GetCs()));
	__vmx_vmwrite(GUEST_DS_BASE, get_segment_base(gdtr.base_address, GetDs()));
	__vmx_vmwrite(GUEST_SS_BASE, get_segment_base(gdtr.base_address, GetSs()));
	__vmx_vmwrite(GUEST_ES_BASE, get_segment_base(gdtr.base_address, GetEs()));

	__vmx_vmwrite(GUEST_CS_AR_BYTES, read_segment_access_rights(GetCs()));
	__vmx_vmwrite(GUEST_SS_AR_BYTES, read_segment_access_rights(GetSs()));
	__vmx_vmwrite(GUEST_DS_AR_BYTES, read_segment_access_rights(GetDs()));
	__vmx_vmwrite(GUEST_ES_AR_BYTES, read_segment_access_rights(GetEs()));
	__vmx_vmwrite(GUEST_FS_AR_BYTES, read_segment_access_rights(GetFs()));
	__vmx_vmwrite(GUEST_GS_AR_BYTES, read_segment_access_rights(GetGs()));
	__vmx_vmwrite(GUEST_LDTR_AR_BYTES, read_segment_access_rights(GetLdtr()));
	__vmx_vmwrite(GUEST_TR_AR_BYTES, read_segment_access_rights(GetTr()));

	__vmx_vmwrite(GUEST_LDTR_BASE, get_segment_base(gdtr.base_address, GetLdtr()));
	__vmx_vmwrite(GUEST_TR_BASE, get_segment_base(gdtr.base_address, GetTr()));


	// Initialize VMCS Host State Area.
	__vmx_vmwrite(HOST_CR0, __readcr0()); // Added by me
	__vmx_vmwrite(HOST_CR3, __readcr3()); // Added by me
	__vmx_vmwrite(HOST_CR4, __readcr4()); // Added by me

	// Fields RPL and TI in host selector fields must be cleared.
	unsigned short host_selector_mask = 7;
	__vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & ~host_selector_mask);
	__vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & ~host_selector_mask);
	__vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & ~host_selector_mask);
	__vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & ~host_selector_mask);
	__vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & ~host_selector_mask);
	__vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & ~host_selector_mask);
	__vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & ~host_selector_mask);

	GetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)Get_GDT_Base());
	__vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

	__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

	__vmx_vmwrite(HOST_GDTR_BASE, Get_GDT_Base());
	__vmx_vmwrite(HOST_IDTR_BASE, Get_IDT_Base());

	// left here just for test
	//UINT64 GUEST_STACK_VA = (UINT64)ExAllocatePoolWithTag(NonPagedPool, 128, POOLTAG);

	//__vmx_vmwrite(GUEST_RSP, (ULONG64)GUEST_STACK_VA + 64);     //setup guest sp
	//__vmx_vmwrite(GUEST_RSP, 0);     //setup guest sp
	//__vmx_vmwrite(GUEST_RIP, (ULONG64)VirtualGuestMemoryAddress);     //setup guest ip



	__vmx_vmwrite(HOST_RSP, ((ULONG64)vmState->VMM_Stack + VMM_STACK_SIZE - 1));
	__vmx_vmwrite(HOST_RIP, (ULONG64)VMExitHandler);

	Status = TRUE;
	//Exit:
	return Status;
}
*/

/*Configure all the required fields of the VMCS*/
BOOLEAN Vmx_Setup_Vmcs(VIRTUAL_MACHINE_STATE* CurrentGuestState, PVOID GuestStack)
{
	BOOLEAN Status = FALSE;

	ULONG64 GdtBase = 0;
	SEGMENT_SELECTOR SegmentSelector = { 0 };

	ULONG CpuBasedVmExecControls;
	ULONG SecondaryProcBasedVmExecControls;


	__vmx_vmwrite(HOST_ES_SELECTOR, AsmGetEs() & 0xF8);
	__vmx_vmwrite(HOST_CS_SELECTOR, AsmGetCs() & 0xF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, AsmGetSs() & 0xF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, AsmGetDs() & 0xF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, AsmGetFs() & 0xF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, AsmGetGs() & 0xF8);
	__vmx_vmwrite(HOST_TR_SELECTOR, AsmGetTr() & 0xF8);

	DbgPrint("Host ES Selector: 0x%x\n", AsmGetEs() & 0xF8);
	DbgPrint("Host CS Selector: 0x%x\n", AsmGetCs() & 0xF8);
	DbgPrint("Host SS Selector: 0x%x\n", AsmGetSs() & 0xF8);
	DbgPrint("Host DS Selector: 0x%x\n", AsmGetDs() & 0xF8);
	DbgPrint("Host FS Selector: 0x%x\n", AsmGetFs() & 0xF8);
	DbgPrint("Host GS Selector: 0x%x\n", AsmGetGs() & 0xF8);
	DbgPrint("Host TR Selector: 0x%x\n", AsmGetTr() & 0xF8);

	// Setting the link pointer to the required value for 4KB VMCS.
	__vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);
	DbgPrint("VMCS Link Pointer: 0x%llx\n", ~0ULL);

	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

	DbgPrint("GUEST_IA32_DEBUGCTL: 0x%llx\n", __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
	DbgPrint("GUEST_IA32_DEBUGCTL_HIGH: 0x%llx\n", __readmsr(MSR_IA32_DEBUGCTL) >> 32);

	//DbgPrint("Debug test 1\n");
	__vmx_vmwrite(GUEST_IA32_PAT, __readmsr(MSR_IA32_CR_PAT));
	__vmx_vmwrite(GUEST_IA32_EFER, __readmsr(MSR_EFER));
	__vmx_vmwrite(GUEST_IA32_PERF_GLOBAL_CTRL, __readmsr(MSR_CORE_PERF_GLOBAL_CTRL));

	//DbgPrint("Debug test 2\n");

	__vmx_vmwrite(HOST_IA32_PAT, __readmsr(MSR_IA32_CR_PAT));
	__vmx_vmwrite(HOST_IA32_EFER, __readmsr(MSR_EFER));
	__vmx_vmwrite(HOST_IA32_PERF_GLOBAL_CTRL, __readmsr(MSR_CORE_PERF_GLOBAL_CTRL));
	
	//DbgPrint("Debug test 3\n");

	DbgPrint("GUEST_IA32_PAT: 0x%llx\n", __readmsr(MSR_IA32_CR_PAT));
	DbgPrint("GUEST_IA32_EFER: 0x%llx\n", __readmsr(MSR_EFER));
	DbgPrint("GUEST_IA32_PERF_GLOBAL_CTRL: 0x%llx\n", __readmsr(MSR_CORE_PERF_GLOBAL_CTRL));
	DbgPrint("HOST_IA32_PAT: 0x%llx\n", __readmsr(MSR_IA32_CR_PAT));
	DbgPrint("HOST_IA32_PERF_GLOBAL_CTRL: 0x%llx\n", __readmsr(MSR_CORE_PERF_GLOBAL_CTRL));

	/* Time-stamp counter offset */
	__vmx_vmwrite(TSC_OFFSET, 0);
	__vmx_vmwrite(TSC_OFFSET_HIGH, 0);

	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

	__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

	__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, 0);


	GdtBase = AsmGetGdtBase();

	DbgPrint("GUEST registers\n");

	BMHV_Fill_Guest_Selector_Data((PVOID)GdtBase, ES, AsmGetEs());
	BMHV_Fill_Guest_Selector_Data((PVOID)GdtBase, CS, AsmGetCs());
	BMHV_Fill_Guest_Selector_Data((PVOID)GdtBase, SS, AsmGetSs());
	BMHV_Fill_Guest_Selector_Data((PVOID)GdtBase, DS, AsmGetDs());
	BMHV_Fill_Guest_Selector_Data((PVOID)GdtBase, FS, AsmGetFs());
	BMHV_Fill_Guest_Selector_Data((PVOID)GdtBase, GS, AsmGetGs());
	BMHV_Fill_Guest_Selector_Data((PVOID)GdtBase, LDTR, AsmGetLdtr());
	BMHV_Fill_Guest_Selector_Data((PVOID)GdtBase, TR, AsmGetTr());

	DbgPrint("end of GUEST registers\n");

	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));

	DbgPrint("GUEST_FS_BASE: 0x%llx\n", __readmsr(MSR_FS_BASE));
	DbgPrint("GUEST_GS_BASE: 0x%llx\n", __readmsr(MSR_GS_BASE));

	__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);   //Active state 
	__vmx_vmwrite(GUEST_PENDING_DBG_EXCEPTIONS, 0);
	__vmx_vmwrite(VMX_PREEMPTION_TIMER_VALUE, 0);
	__vmx_vmwrite(GUEST_INTR_STATUS, 0);
	__vmx_vmwrite(GUEST_PML_INDEX, 0);


	IA32_VMX_BASIC_MSR capability_msr;
	capability_msr.All = __readmsr(MSR_IA32_VMX_BASIC);
	DbgPrint("Capability MSR . True VMX Controls : %d\n", capability_msr.Fields.VmxCapabilityHint);

	CpuBasedVmExecControls = BMHV_Adjust_Controls(CPU_BASED_ACTIVATE_MSR_BITMAP |  
		CPU_BASED_ACTIVATE_SECONDARY_CONTROLS /* |
		CPU_BASED_ACTIVATE_IO_BITMAP*/, capability_msr.Fields.VmxCapabilityHint == 0 ? MSR_IA32_VMX_PROCBASED_CTLS : MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, CpuBasedVmExecControls);

	//__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, HvAdjustControls(CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS , capability_msr.Fields.VmxCapabilityHint == 0 ? MSR_IA32_VMX_PROCBASED_CTLS : MSR_IA32_VMX_TRUE_PROCBASED_CTLS));
	LogInfo("Cpu Based VM Exec Controls : 0x%lx", CpuBasedVmExecControls);

	SecondaryProcBasedVmExecControls = BMHV_Adjust_Controls(CPU_BASED_CTL2_RDTSCP |
		CPU_BASED_CTL2_ENABLE_EPT | CPU_BASED_CTL2_ENABLE_INVPCID |
		CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS, MSR_IA32_VMX_PROCBASED_CTLS2);

	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, SecondaryProcBasedVmExecControls);
	
	//__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, HvAdjustControls(CPU_BASED_CTL2_RDTSCP | CPU_BASED_CTL2_ENABLE_INVPCID | CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS, MSR_IA32_VMX_PROCBASED_CTLS2));
	LogInfo("Secondary Proc Based VM Exec Controls (MSR_IA32_VMX_PROCBASED_CTLS2) : 0x%x", SecondaryProcBasedVmExecControls);

	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, BMHV_Adjust_Controls(0, capability_msr.Fields.VmxCapabilityHint == 0 ? MSR_IA32_VMX_PINBASED_CTLS : MSR_IA32_VMX_TRUE_PINBASED_CTLS));
	__vmx_vmwrite(VM_EXIT_CONTROLS, BMHV_Adjust_Controls(VM_EXIT_IA32E_MODE | VM_EXIT_HOST_ADDR_SPACE_SIZE /* | VM_EXIT_ACK_INTR_ON_EXIT */, capability_msr.Fields.VmxCapabilityHint == 0 ? MSR_IA32_VMX_EXIT_CTLS : MSR_IA32_VMX_TRUE_EXIT_CTLS));

	//IA-32 mode enables the processor to run in protected mode and virtual real mode. IA-32e mode allows the processor to run in 64-bit mode and compatibility mode, which means you can run both 64-bit and 32-bit applications simultaneously.
	__vmx_vmwrite(VM_ENTRY_CONTROLS, BMHV_Adjust_Controls(VM_ENTRY_IA32E_MODE, capability_msr.Fields.VmxCapabilityHint == 0 ? MSR_IA32_VMX_ENTRY_CTLS : MSR_IA32_VMX_TRUE_ENTRY_CTLS));


	
	
	
	__vmx_vmwrite(CR0_GUEST_HOST_MASK, 0);
	__vmx_vmwrite(CR4_GUEST_HOST_MASK, 0);

	__vmx_vmwrite(CR0_READ_SHADOW, __readcr0());
	__vmx_vmwrite(CR4_READ_SHADOW, __readcr4());

	DbgPrint("PIN_BASED_VM_EXEC_CONTROL: 0x%x\n", BMHV_Adjust_Controls(0, MSR_IA32_VMX_PINBASED_CTLS));
	//DbgPrint("VM_EXIT_CONTROLS: 0x%x\n", exit_controls.control);
	//DbgPrint("VM_ENTRY_CONTROLS: 0x%x\n", entry_controls.control);
	DbgPrint("CR0_READ_SHADOW: 0x%llx\n", __readcr0());
	DbgPrint("CR4_READ_SHADOW: 0x%llx\n", __readcr4());

	//Exception bitmap - This is a 32 - bit field in which one bit is for each exception.Setting this will define which exception should cause vmexit.We are just going to set it up to 0 to ignore vmexit for any guest exception.
	//__vmx_vmwrite(EXCEPTION_BITMAP, 0);

	__vmx_vmwrite(CR3_TARGET_COUNT, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE0, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE1, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE2, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE3, 0);


	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());

	__vmx_vmwrite(GUEST_DR7, 0x400);

	/*
	Because we may be executing in an arbitrary user-mode, process as part
	of the DPC interrupt we execute in We have to save Cr3, for HOST_CR3
	*/

	__vmx_vmwrite(HOST_CR3, InitiateCr3);

	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR4, __readcr4());

	DbgPrint("Cr0: 0x%llx\n", __readcr0());
	DbgPrint("Cr3: 0x%llx\n", __readcr3());
	DbgPrint("Cr4: 0x%llx\n", __readcr4());

	__vmx_vmwrite(GUEST_GDTR_BASE, AsmGetGdtBase());
	__vmx_vmwrite(GUEST_IDTR_BASE, AsmGetIdtBase());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, AsmGetGdtLimit());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, AsmGetIdtLimit());

	__vmx_vmwrite(GUEST_RFLAGS, AsmGetRflags());

	//DbgPrint("GUEST_GDTR_BASE: 0x%llx\n", Get_GDT_Base());
	//DbgPrint("GUEST_IDTR_BASE: 0x%llx\n", Get_IDT_Base());
	//DbgPrint("GUEST_GDTR_LIMIT: 0x%x\n", Get_GDT_Limit());
	//DbgPrint("GUEST_IDTR_LIMIT: 0x%x\n", Get_IDT_Limit());
	//DbgPrint("GUEST_RFLAGS: 0x%llx\n", Get_RFLAGS());

	BMHV_Get_Segment_Descriptor(&SegmentSelector, AsmGetTr(), (PUCHAR)AsmGetGdtBase());
	__vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

	__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

	__vmx_vmwrite(HOST_GDTR_BASE, AsmGetGdtBase());
	__vmx_vmwrite(HOST_IDTR_BASE, AsmGetIdtBase());

	//DbgPrint("HOST_TR_BASE: 0x%llx\n", SegmentSelector.BASE);
	DbgPrint("HOST_FS_BASE: 0x%llx\n", __readmsr(MSR_FS_BASE));
	DbgPrint("HOST_GS_BASE: 0x%llx\n", __readmsr(MSR_GS_BASE));
	//DbgPrint("HOST_GDTR_BASE: 0x%llx\n", Get_GDT_Base());
	//DbgPrint("HOST_IDTR_BASE: 0x%llx\n", Get_IDT_Base());

	//same values for guest and host MSR's
	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

	__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

	DbgPrint("HOST_IA32_SYSENTER_CS: 0x%llx\n", __readmsr(MSR_IA32_SYSENTER_CS));
	DbgPrint("HOST_IA32_SYSENTER_EIP: 0x%llx\n", __readmsr(MSR_IA32_SYSENTER_EIP));
	DbgPrint("HOST_IA32_SYSENTER_ESP: 0x%llx\n", __readmsr(MSR_IA32_SYSENTER_ESP));
	DbgPrint("====================================================================================================\n");
	DbgPrint("====================================================================================================\n");

	// Set MSR Bitmaps
	__vmx_vmwrite(MSR_BITMAP, CurrentGuestState->MsrBitmapPhysicalAddress);
	//__vmx_vmwrite(IO_BITMAP_A, CurrentGuestState->IOBitmapPhysicalAddressA);
	//__vmx_vmwrite(IO_BITMAP_B, CurrentGuestState->IOBitmapPhysicalAddressB);


	// Set exception bitmap to hook division by zero (bit 1 of EXCEPTION_BITMAP)
	__vmx_vmwrite(EXCEPTION_BITMAP, 0x9); // breakpoint 3nd bit //1001

	// Set up EPT 
	__vmx_vmwrite(EPT_POINTER, EptState->EptPointer.Flags);

	__vmx_vmwrite(GUEST_RSP, (ULONG64)GuestStack);     // setup guest sp
	//__vmx_vmwrite(GUEST_RIP, (ULONG64)RestoreStateOfVMXLabel);     //setup guest ip
	__vmx_vmwrite(GUEST_RIP, (ULONG64)AsmVmxRestoreState);

	__vmx_vmwrite(HOST_RSP, ((ULONG64)CurrentGuestState->VmmStack + VMM_STACK_SIZE - 1));
	__vmx_vmwrite(HOST_RIP, (ULONG64)AsmVmexitHandler);

	Status = TRUE;
//Exit:
	return Status;
}


/*To resume the guest VM*/
VOID Vmx_VMResume(VOID)
{
	ULONG64 ErrorCode;
	//DbgPrint("VM Resumed\n");
	__vmx_vmresume();

	// if VMRESUME succeed will never be here !

	ErrorCode = 0;
	__vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
	__vmx_off();
	LogError("Error in executing Vmresume , status : 0x%llx", ErrorCode);

	// It's such a bad error because we don't where to go !
	// prefer to break
	DbgBreakPoint();
}


//Prepare and execute Vmxoff instruction
VOID Vmx_Vmxoff()
{
	int CurrentProcessorIndex;
	UINT64 GuestRSP; 	// Save a pointer to guest rsp for times that we want to return to previous guest stateS
	UINT64 GuestRIP; 	// Save a pointer to guest rip for times that we want to return to previous guest state
	UINT64 GuestCr3;
	UINT64 ExitInstructionLength;


	// Initialize the variables
	ExitInstructionLength = 0;
	GuestRIP = 0;
	GuestRSP = 0;

	CurrentProcessorIndex = KeGetCurrentProcessorNumber();

	/*
	According to SimpleVisor :
		Our callback routine may have interrupted an arbitrary user process,
		and therefore not a thread running with a system-wide page directory.
		Therefore if we return back to the original caller after turning off
		VMX, it will keep our current "host" CR3 value which we set on entry
		to the PML4 of the SYSTEM process. We want to return back with the
		correct value of the "guest" CR3, so that the currently executing
		process continues to run with its expected address space mappings.
	*/

	__vmx_vmread(GUEST_CR3, &GuestCr3);
	__writecr3(GuestCr3);

	// Read guest rsp and rip
	__vmx_vmread(GUEST_RIP, &GuestRIP);
	__vmx_vmread(GUEST_RSP, &GuestRSP);

	// Read instruction length
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);
	GuestRIP += ExitInstructionLength;

	// Set the previous registe states
	GuestState[CurrentProcessorIndex].VmxoffState.GuestRip = GuestRIP;
	GuestState[CurrentProcessorIndex].VmxoffState.GuestRsp = GuestRSP;

	// Notify the Vmexit handler that VMX already turned off
	GuestState[CurrentProcessorIndex].VmxoffState.IsVmxoffExecuted = TRUE;

	// Execute Vmxoff
	__vmx_off();

}

/*MTF - Monitor Trap Guy*/
/*MTF instruction causes VM Exit after executing one instruction*/
VOID ApplyHookAfterMTF() {
	VMX_ROOT = TRUE;
	EptPageHook(ExAllocatePoolWithTag, TRUE);
	///////////////////////////////////////////////////////////////////
	//SecretData = L"Hooked ExAllocatePoolWithTag function again using MTF\n";
	DbgPrint("Hooked ExAllocatePoolWithTag function again using MTF\n");
}

/* Main Vmexit events handler */
/*Handles all VM Exit cases, it handles the case and then resumes the guest VM*/
BOOLEAN Vmx_Vm_exit_Handler(PGUEST_REGS GuestRegs)
{
	//DbgPrint("VM Exit\n");
	int CurrentProcessorIndex;
	UINT64 GuestPhysicalAddr;
	UINT64 GuestRip;
	ULONG ExitReason;
	ULONG ExitQualification;
	ULONG Rflags;
	ULONG EcxReg;
	ULONG ExitInstructionLength;
	VMEXIT_INTERRUPT_INFO InterruptExit;
	VMX_EXIT_QUALIFICATION_IO_INSTRUCTION IoQualification;

	CurrentProcessorIndex = KeGetCurrentProcessorNumber();

	// Indicates we are in Vmx root mode in this logical core
	GuestState[CurrentProcessorIndex].IsOnVmxRootMode = TRUE;

	GuestState[CurrentProcessorIndex].IncrementRip = TRUE;

	ExitReason = 0;
	__vmx_vmread(VM_EXIT_REASON, &ExitReason);

	ExitQualification = 0;
	__vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);

	ExitReason &= 0xffff;

	// Debugging purpose
	//LogInfo("VM_EXIT_REASON : 0x%llx", ExitReason);
	//LogInfo("EXIT_QUALIFICATION : 0x%llx", ExitQualification);

	switch (ExitReason)
	{
	case EXIT_REASON_TRIPLE_FAULT:
	{
		DbgPrint("VM Exit Reason : Triple Fault\n");
		DbgBreakPoint();
		break;
	}

	// 25.1.2  Instructions That Cause VM Exits Unconditionally
	// The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
	// INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID, 
	// VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.

	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
	case EXIT_REASON_VMLAUNCH:
	{
		DbgPrint("VM Exit Reason : Use of VMX intruction in VMX non root\n");
		/* Target guest tries to execute VM Instruction, it probably causes a fatal error or system halt as the system might
		   think it has VMX feature enabled while it's not available due to our use of hypervisor.	*/

		Rflags = 0;
		__vmx_vmread(GUEST_RFLAGS, &Rflags);
		__vmx_vmwrite(GUEST_RFLAGS, Rflags | 0x1); // cf=1 indicate vm instructions fail
		break;
	}

	case EXIT_REASON_CR_ACCESS:
	{
		DbgPrint("VM Exit Reason : CR Access\n");
		DbgBreakPoint();
		BMHV_Handle_Control_Register_Access(GuestRegs);
		break;
	}
	case EXIT_REASON_MSR_READ:
	{
		//DbgPrint("Exit Reason : MSR Read\n");
		EcxReg = GuestRegs->rcx & 0xffffffff;
		BMHV_Handle_Msr_Read(GuestRegs);

		break;
	}
	case EXIT_REASON_MSR_WRITE:
	{
		DbgPrint("VM Exit Reason : MSR Write\n");
		EcxReg = GuestRegs->rcx & 0xffffffff;
		BMHV_Handle_Msr_Write(GuestRegs);

		break;
	}
	case EXIT_REASON_CPUID:
	{
		DbgPrint("VM Exit Reason : CPUID\n");
		PCHAR msgData = "CPUID Access\n";
		if (secretDataLength < 250) {
			for (int i = 0; i < strlen(msgData); i++) {
				SecretData[secretDataLength] = *(msgData + i);
				secretDataLength += 1;
			}
		}
		
		
		BMHV_Handle_Cpuid_Call(GuestRegs);

		/***  It's better to turn off hypervisor from Vmcall ***/

		/*
		VmexitStatus = HvHandleCpuid(GuestRegs);
		// Detect whether we have to turn off VMX or Not
		if (VmexitStatus)
		{
			// We have to save GUEST_RIP & GUEST_RSP somewhere to restore them directly
			ExitInstructionLength = 0;
			GuestRIP = 0;
			GuestRSP = 0;
			__vmx_vmread(GUEST_RIP, &GuestRIP);
			__vmx_vmread(GUEST_RSP, &GuestRSP);
			__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);
			GuestRIP += ExitInstructionLength;
		}
		*/
		break;
	}

	case EXIT_REASON_IO_INSTRUCTION:
	{
		DbgPrint("VM Exit Reason : IO Instruction\n");
		LogInfo("EXIT_QUALIFICATION : 0x%llx\n", ExitQualification);
		IoQualification.Flags = ExitQualification;
		DbgPrint("SizeOfAccess : 0x%llx\n AccessType : 0x%llx\n StringInstruction : 0x %llx\n RepPrefixed : 0x%llx; OperandEncoding : 0x%llx\n Reserved1 : 0x%llx\n PortNumber : 0x%llx\n", IoQualification.SizeOfAccess, IoQualification.AccessType, IoQualification.StringInstruction, IoQualification.RepPrefixed, IoQualification.OperandEncoding, IoQualification.Reserved1, IoQualification.PortNumber);
		AddToSecretData("IO Instruction Executed", -1);
		AddToSecretData("Port Number : ", IoQualification.PortNumber);
		break;
	}
	case EXIT_REASON_EPT_VIOLATION:
	{

		//wcsncat(SecretData, L" EPT Violations\n", 20);
		DbgPrint("====================================================================================================\n");
		PCHAR msgData = "EPT Violation\n";
		for (int i = 0; i < strlen(msgData); i++) {
			SecretData[secretDataLength] = *(msgData + i);
			secretDataLength += 1;
		}
		
		DbgPrint("VM Exit Reason : EPT Violation\n");
		// Reading guest physical address
		GuestPhysicalAddr = 0;
		__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &GuestPhysicalAddr);
		LogInfo("VM Guest Physical Address : 0x%llx", GuestPhysicalAddr);
		AddToSecretData("VM Guest Physical Address : 0x", GuestPhysicalAddr);
		// Reading guest's RIP 
		GuestRip = 0;
		__vmx_vmread(GUEST_RIP, &GuestRip);
		LogInfo("Guest Rip : 0x%llx", GuestRip);
		AddToSecretData("Guest IP : 0x", GuestRip);
		if (!EptHandleEptViolation(ExitQualification, GuestPhysicalAddr))
		{
			LogError("There were errors in handling Ept Violation");
		}
		DbgPrint("====================================================================================================\n");
		break;
	}
	case EXIT_REASON_EPT_MISCONFIG:
	{
		DbgPrint("VM Exit Reason : EPT Misconfig\n");
		GuestPhysicalAddr = 0;
		__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &GuestPhysicalAddr);

		EptHandleMisconfiguration(GuestPhysicalAddr);

		break;
	}
	case EXIT_REASON_VMCALL:
	{
		//wcsncat(SecretData, L" VM Call Executed\n", 20);
		PCHAR msgData = "VM Call Executed\n";
		for (int i = 0; i < strlen(msgData); i++) {
			SecretData[secretDataLength] = *(msgData + i);
			secretDataLength += 1;
		}
		
		DbgPrint("VM Exit Reason : VMCALL\n");
		GuestRegs->rax = VMCALL_Handler_For_VMX(GuestRegs->rcx, GuestRegs->rdx, GuestRegs->r8, GuestRegs->r9);
		break;
	}
	case EXIT_REASON_MONITOR_TRAP_FLAG:
	{
		DbgPrint("VM Exit : Monitor Trap Flag\n");
		/* Monitor Trap Flag */
		ApplyHookAfterMTF();

		// Redo the instruction 
		GuestState[CurrentProcessorIndex].IncrementRip = FALSE;

		// We don't need MTF anymore
		BMHV_Set_Monitor_Trap_Flag(FALSE);

		break;
	}
	case EXIT_REASON_EXCEPTION_NMI:
	{
		DbgPrint("====================================================================================================\n");
		DbgPrint("VM Exit : NMI\n");
		AddToSecretData("Non-maskable interrupt (NMI) took place",-1);
		/*

		Exception or non-maskable interrupt (NMI). Either:
			1: Guest software caused an exception and the bit in the exception bitmap associated with exception’s vector was set to 1
			2: An NMI was delivered to the logical processor and the “NMI exiting” VM-execution control was 1.

		VM_EXIT_INTR_INFO shows the exit infromation about event that occured and causes this exit
		Don't forget to read VM_EXIT_INTR_ERROR_CODE in the case of re-injectiong event

		*/

		// read the exit reason
		__vmx_vmread(VM_EXIT_INTR_INFO, &InterruptExit);

		if (InterruptExit.InterruptionType == INTERRUPT_TYPE_SOFTWARE_EXCEPTION && InterruptExit.Vector == EXCEPTION_VECTOR_BREAKPOINT)
		{

			ULONG64 GuestRip;
			// Reading guest's RIP 
			__vmx_vmread(GUEST_RIP, &GuestRip);

			// Send the user
			LogInfo("Breakpoint Hit (Process Id : 0x%x) at : %llx ", PsGetCurrentProcessId(), GuestRip);
			AddToSecretData("Breakpoint Hit ,Process Id : 0x", PsGetCurrentProcessId());
			AddToSecretData("IP : ", GuestRip);
			GuestState[CurrentProcessorIndex].IncrementRip = FALSE;

			// re-inject #BP back to the guest
			Event_Inject_Break_point();

		}
		else if (InterruptExit.InterruptionType == INTERRUPT_TYPE_HARDWARE_EXCEPTION && InterruptExit.Vector == EXCEPTION_DIVIDED_BY_ZERO)
		{

			ULONG64 GuestRip;
			// Reading guest's RIP 
			__vmx_vmread(GUEST_RIP, &GuestRip);

			// Send the user
			LogInfo("Divided By Zero (Process Id : 0x%x) at : %llx ", PsGetCurrentProcessId(), GuestRip);
			AddToSecretData("Divided By Zero ,Process Id : 0x", PsGetCurrentProcessId());
			AddToSecretData("IP : ", GuestRip);
			GuestState[CurrentProcessorIndex].IncrementRip = TRUE;

			// re-inject #BP back to the guest
			Event_Inject_Divide_By_Zero();

		}
		else
		{
			LogError("Not expected event occured");
		}
		DbgPrint("====================================================================================================\n");
		break;
	}
	default:
	{
		LogWarning("Unkown Vmexit, reason : 0x%llx", ExitReason);
		DbgBreakPoint();
		break;
	}
	}

	if (!GuestState[CurrentProcessorIndex].VmxoffState.IsVmxoffExecuted && GuestState[CurrentProcessorIndex].IncrementRip)
	{
		BMHV_Resume_To_Next_Instruction();
	}

	// Set indicator of Vmx noon root mode to false
	GuestState[CurrentProcessorIndex].IsOnVmxRootMode = FALSE;

	if (GuestState[CurrentProcessorIndex].VmxoffState.IsVmxoffExecuted)
	{
		return TRUE;
	}

	return FALSE;
}

/*
//debug test
//fixed now
static void vmx_adjust_entry_controls(union __vmx_entry_control_t* entry_controls)
{
	unsigned int capability_msr;
	union __vmx_basic_msr_t basic;

	basic.control = __readmsr(MSR_IA32_VMX_BASIC);
	capability_msr = (basic.bits.true_controls != FALSE) ? MSR_IA32_VMX_TRUE_ENTRY_CTLS : MSR_IA32_VMX_ENTRY_CTLS;

	entry_controls->control = vmx_adjust_cv(capability_msr, entry_controls->control);
}

static void vmx_adjust_exit_controls(union __vmx_exit_control_t* exit_controls)
{
	unsigned int capability_msr;
	union __vmx_basic_msr_t basic;
	basic.control = __readmsr(MSR_IA32_VMX_BASIC);
	capability_msr = (basic.bits.true_controls != FALSE) ? MSR_IA32_VMX_TRUE_EXIT_CTLS : MSR_IA32_VMX_EXIT_CTLS;
	exit_controls->control = vmx_adjust_cv(capability_msr, exit_controls->control);
}

void vmx_adjust_pinbased_controls(union __vmx_pinbased_control_msr_t* exit_controls)
{
	unsigned int capability_msr;
	union __vmx_basic_msr_t basic;
	basic.control = __readmsr(MSR_IA32_VMX_BASIC);
	capability_msr = (basic.bits.true_controls != FALSE) ? MSR_IA32_VMX_TRUE_PINBASED_CTLS : MSR_IA32_VMX_PINBASED_CTLS;
	exit_controls->control = vmx_adjust_cv(capability_msr, exit_controls->control);
}

static unsigned __int64 vmx_adjust_cv(unsigned int capability_msr, unsigned __int64 value)
{
	union __vmx_true_control_settings_t cap;
	unsigned __int64 actual;

	cap.control = __readmsr(capability_msr);
	actual = value;

	actual |= cap.allowed_0_settings;
	actual &= cap.allowed_1_settings;

	return actual;
}
static unsigned __int64 get_segment_base(unsigned __int64 gdt_base, unsigned __int16 segment_selector)
{
	unsigned __int64 segment_base;
	union __segment_selector_t selector;
	struct __segment_descriptor_32_t* descriptor;
	struct __segment_descriptor_32_t* descriptor_table;

	selector.flags = segment_selector;

	if (selector.table == 0
		&& selector.index == 0)
	{
		segment_base = 0;
		return segment_base;
	}

	descriptor_table = (struct __segment_descriptor_32_t*)gdt_base;
	descriptor = &descriptor_table[selector.index];

	//
	// All of this bit masking and shifting is just a shortcut instead
	// of allocating some local variables to hold the low, mid, and high base
	// values. 
	//
	// If we did it with local variables it would look similar to this:
	// base_high = descriptor->base_high << 24;
	// base_mid = descriptor->base_middle << 16;
	// base_low = descriptor->base_low;
	// segment_base = (base_high | base_mid | base_low) & 0xFFFFFFFF;
	//
	// But for the purposes of doing it all in one fell-swoop we did the shifting
	// and masking inline.
	//
	segment_base = (unsigned __int64)((descriptor->base_high & 0xFF000000) |
		((descriptor->base_middle << 16) & 0x00FF0000) |
		((descriptor->base_low >> 16) & 0x0000FFFF));

	//
	// As mentioned in the discussion in the article, some system descriptors are expanded
	// to 16 bytes on Intel 64 architecture. We only need to pay attention to the TSS descriptors
	// and we'll use our expanded descriptor structure to adjust the segment base.
	//
	if ((descriptor->system == 0) &&
		((descriptor->type == SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE) ||
			(descriptor->type == SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY)))
	{
		struct __segment_descriptor_64_t* expanded_descriptor;
		expanded_descriptor = (struct __segment_descriptor_64_t*)descriptor;
		segment_base |= ((unsigned __int64)expanded_descriptor->base_upper << 32);
	}

	return segment_base;
}
*/
/*
static unsigned __int32 read_segment_access_rights(unsigned __int16 segment_selector)
{
	union __segment_selector_t selector;
	union __segment_access_rights_t vmx_access_rights;

	selector.flags = segment_selector;

	//
	// Check for null selector use, if found set access right to unusable
	// and return. Otherwise, get access rights, modify format, return the
	// segment access rights.
	//
	if (selector.table == 0
		&& selector.index == 0)
	{
		vmx_access_rights.flags = 0;
		vmx_access_rights.unusable = TRUE;
		return vmx_access_rights.flags;
	}

	//
	// Use our custom intrinsic to store our access rights, and
	// remember that the first byte of the access rights returned
	// are not used in VMX access right format.
	//
	vmx_access_rights.flags = (__load_ar(segment_selector) >> 8);
	vmx_access_rights.unusable = 0;
	vmx_access_rights.reserved0 = 0;
	vmx_access_rights.reserved1 = 0;

	return vmx_access_rights.flags;
}

*/
