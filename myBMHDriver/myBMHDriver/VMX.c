#include "MSR.h"
#include "CPU.h"
#include "Common.h"
#include "EPT.h"
#include "BMHDriver.h"
#include "VMX.h"
#include "intrin.h"

PVirtualMachineState vmState;
int ProcessorCounts;


void Initiate_VMX(void) {

	if (!Is_VMX_Supported())
	{
		DbgPrint("[*] VMX is not supported in this machine ! \n");
		return;
	}

	ProcessorCounts = KeQueryActiveProcessorCount(0);
	vmState = ExAllocatePoolWithTag(NonPagedPool, sizeof(VirtualMachineState) * ProcessorCounts, POOLTAG); //struct array

	DbgPrint("[*] Count of logical processor is %d \n", ProcessorCounts);
	DbgPrint("\n=====================================================\n");

	KAFFINITY kAffinityMask;
	for (size_t i = 0; i < ProcessorCounts; i++)
	{
		kAffinityMask = power(2, i);
		KeSetSystemAffinityThread(kAffinityMask);
		// do st here !
		//DbgPrint("\t\tCurrent thread is executing in %d th logical processor. \n", i);
		printCurrentExecutingLogicalProcessor(i);
		Enable_VMX_Operation();	// Enabling VMX Operation
		DbgPrint("[*] VMX Operation Enabled Successfully ! \n");

		Allocate_VMXON_Region(&vmState[i]);
		Allocate_VMCS_Region(&vmState[i]);


		DbgPrint("[*] VMCS Region is allocated at  ===============> %llx \n", vmState[i].VMCS_REGION);
		DbgPrint("[*] VMXON Region is allocated at ===============> %llx \n", vmState[i].VMXON_REGION);

		DbgPrint("\n=====================================================\n");

	}

}


void Terminate_VMX(void) {

	DbgPrint("\n[*] Terminating VMX...\n");

	KAFFINITY kAffinityMask;
	for (size_t i = 0; i < ProcessorCounts; i++)
	{
		kAffinityMask = power(2, i);
		KeSetSystemAffinityThread(kAffinityMask);
		//DbgPrint("\t\tCurrent thread is executing in %d th logical processor.\n", i);
		printCurrentExecutingLogicalProcessor(i);

		__vmx_off();
		MmFreeContiguousMemory((PVOID)PhysicalAddress_to_VirtualAddress(vmState[i].VMXON_REGION));
		MmFreeContiguousMemory((PVOID)PhysicalAddress_to_VirtualAddress(vmState[i].VMCS_REGION));

	}

	DbgPrint("[*] VMX Operation turned off successfully. \n");

}





void LaunchVM(int ProcessorID, PEPTP EPTP) {

	DbgPrint("\n======================== Launching VM =============================\n");

	KAFFINITY kAffinityMask;
	kAffinityMask = power(2, ProcessorID);
	KeSetSystemAffinityThread(kAffinityMask);

	DbgPrint("[*]\t\tCurrent thread is executing in %d th logical processor.\n", ProcessorID);

	PAGED_CODE();

	// Get read of nasty interrupts :)
	//	CLI_Instruction();

	// Allocate stack for the VM Exit Handler.
	UINT64 VMM_STACK_VA = (UINT64)ExAllocatePoolWithTag(NonPagedPool, VMM_STACK_SIZE, POOLTAG);
	vmState[ProcessorID].VMM_Stack = VMM_STACK_VA;

	if ((void*)(vmState[ProcessorID].VMM_Stack) == NULL)
	{
		DbgPrint("[*] Error in allocating VMM Stack.\n");
		return;
	}
	RtlZeroMemory((void *)(vmState[ProcessorID].VMM_Stack), VMM_STACK_SIZE);

	// Allocate memory for MSRBitMap
	vmState[ProcessorID].MSRBitMap = (UINT64)MmAllocateNonCachedMemory(PAGE_SIZE);  // should be aligned
	if ((void *)(vmState[ProcessorID].MSRBitMap) == NULL)
	{
		DbgPrint("[*] Error in allocating MSRBitMap.\n");
		return;
	}
	RtlZeroMemory((void*)(vmState[ProcessorID].MSRBitMap), PAGE_SIZE);
	vmState[ProcessorID].MSRBitMapPhysical = VirtualAddress_to_PhysicalAddress((void*)(vmState[ProcessorID].MSRBitMap));



	// Clear the VMCS State
	if (!Clear_VMCS_State(&vmState[ProcessorID])) {
		goto ErrorReturn;
	}

	// Load VMCS (Set the Current VMCS)
	if (!Load_VMCS(&vmState[ProcessorID]))
	{
		goto ErrorReturn;
	}


	DbgPrint("[*] Setting up VMCS.\n");
	Setup_VMCS(&vmState[ProcessorID], EPTP);



	DbgPrint("[*] Executing VMLAUNCH.\n");

	//assembly fn to save the current sp and bp for returning
	Save_VMXOFF_State();

	__vmx_vmlaunch();

	// if VMLAUNCH succeed will never be here !
	ULONG64 ErrorCode = 0;
	__vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
	__vmx_off();
	DbgPrint("[*] VMLAUNCH Error : 0x%llx\n", ErrorCode);
	DbgBreakPoint();

	DbgPrint("\n===================================================================\n");
	goto ErrorReturn;
	// Start responsing to interrupts
	// STI_Instruction();


ReturnWithoutError:
	__vmx_off();
	DbgPrint("[*] VMXOFF Executed Successfully. !\n");
	return TRUE;
	// Return With Error
ErrorReturn:
	DbgPrint("[*] Fail to setup VMCS !\n");
	return FALSE;
}


UINT64 VMPTRST()
{
	PHYSICAL_ADDRESS vmcspa;
	vmcspa.QuadPart = 0;
	__vmx_vmptrst((unsigned __int64*)&vmcspa);

	DbgPrint("[*] VMPTRST %llx\n", vmcspa);

	return 0;
}

BOOLEAN Clear_VMCS_State(IN PVirtualMachineState vmState) {

	// Clear the state of the VMCS to inactive
	int status = __vmx_vmclear(&vmState->VMCS_REGION);

	DbgPrint("[*] VMCS VMCLAEAR Status is : %d\n", status);
	if (status)
	{
		// Otherwise terminate the VMX
		DbgPrint("[*] VMCS failed to clear with status %d\n", status);
		__vmx_off();
		return FALSE;
	}
	return TRUE;
}

BOOLEAN Load_VMCS(IN PVirtualMachineState vmState) {

	int status = __vmx_vmptrld(&vmState->VMCS_REGION);
	if (status)
	{
		DbgPrint("[*] VMCS failed with status %d\n", status);
		return FALSE;
	}
	return TRUE;
}

BOOLEAN GetSegmentDescriptor(IN PSEGMENT_SELECTOR SegmentSelector, IN USHORT Selector, IN PUCHAR GdtBase)
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

BOOLEAN SetGuestSelector(IN PVOID GDT_Base, IN ULONG Segment_Register, IN USHORT Selector)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG            uAccessRights;

	GetSegmentDescriptor(&SegmentSelector, Selector, GDT_Base);
	uAccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

	if (!Selector)
		uAccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + Segment_Register * 2, Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT + Segment_Register * 2, SegmentSelector.LIMIT);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + Segment_Register * 2, uAccessRights);
	__vmx_vmwrite(GUEST_ES_BASE + Segment_Register * 2, SegmentSelector.BASE);

	return TRUE;
}

ULONG AdjustControls(IN ULONG Ctl, IN ULONG Msr)
{
	MSR MsrValue = { 0 };

	MsrValue.Content = __readmsr(Msr);
	Ctl &= MsrValue.High;     /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.Low;      /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}

void FillGuestSelectorData(
	__in PVOID GdtBase,
	__in ULONG Segreg,
	__in USHORT Selector
)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG            uAccessRights;

	GetSegmentDescriptor(&SegmentSelector, Selector, GdtBase);
	uAccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

	if (!Selector)
		uAccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, uAccessRights);
	__vmx_vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);

	DbgPrint("Selector: 0x%x\n", Selector);
	DbgPrint("Limit: 0x%x\n", SegmentSelector.LIMIT);
	DbgPrint("Access rights: 0x%x\n", uAccessRights);
	DbgPrint("Base: 0x%x\n", SegmentSelector.BASE);


}
BOOLEAN Setup_VMCS_Attempt(IN PVirtualMachineState vmState, IN PEPTP EPTP) {
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

	//missed secondary processor*/

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
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, secondary_controls.control);*/

	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_ACTIVATE_MSR_BITMAP, MSR_IA32_VMX_PROCBASED_CTLS));
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP /* | CPU_BASED_CTL2_ENABLE_EPT*/, MSR_IA32_VMX_PROCBASED_CTLS2));

	
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
BOOLEAN Setup_VMCS(IN PVirtualMachineState vmState, IN PEPTP EPTP) {


	BOOLEAN Status = FALSE;


	// Load Extended Page Table Pointer
	//__vmx_vmwrite(EPT_POINTER, EPTP->All);

	ULONG64 GdtBase = 0;
	SEGMENT_SELECTOR SegmentSelector = { 0 };


	__vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & 0xF8);
	__vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & 0xF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & 0xF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & 0xF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & 0xF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & 0xF8);
	__vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & 0xF8);

	DbgPrint("Host ES Selector: 0x%x\n", GetEs() & 0xF8);
	DbgPrint("Host CS Selector: 0x%x\n", GetCs() & 0xF8);
	DbgPrint("Host SS Selector: 0x%x\n", GetSs() & 0xF8);
	DbgPrint("Host DS Selector: 0x%x\n", GetDs() & 0xF8);
	DbgPrint("Host FS Selector: 0x%x\n", GetFs() & 0xF8);
	DbgPrint("Host GS Selector: 0x%x\n", GetGs() & 0xF8);
	DbgPrint("Host TR Selector: 0x%x\n", GetTr() & 0xF8);

	// Setting the link pointer to the required value for 4KB VMCS.
	__vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);
	DbgPrint("VMCS Link Pointer: 0x%x\n", ~0ULL);

	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

	DbgPrint("GUEST_IA32_DEBUGCTL: 0x%x\n", __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
	DbgPrint("GUEST_IA32_DEBUGCTL_HIGH: 0x%x\n", __readmsr(MSR_IA32_DEBUGCTL) >> 32);

	DbgPrint("[*] test 1\n");
	__vmx_vmwrite(GUEST_IA32_PAT, __readmsr(MSR_IA32_CR_PAT));
	__vmx_vmwrite(GUEST_IA32_EFER, __readmsr(MSR_EFER));
	__vmx_vmwrite(GUEST_IA32_PERF_GLOBAL_CTRL, __readmsr(MSR_CORE_PERF_GLOBAL_CTRL));
	DbgPrint("[*] test 2\n");
	__vmx_vmwrite(HOST_IA32_PAT, __readmsr(MSR_IA32_CR_PAT));
	__vmx_vmwrite(HOST_IA32_EFER, __readmsr(MSR_EFER));
	__vmx_vmwrite(HOST_IA32_PERF_GLOBAL_CTRL, __readmsr(MSR_CORE_PERF_GLOBAL_CTRL));
	
	DbgPrint("[*] test 3\n");
	DbgPrint("GUEST_IA32_PAT: 0x%x\n", __readmsr(MSR_IA32_CR_PAT));
	DbgPrint("GUEST_IA32_EFER: 0x%x\n", __readmsr(MSR_EFER));
	DbgPrint("GUEST_IA32_PERF_GLOBAL_CTRL: 0x%x\n", __readmsr(MSR_CORE_PERF_GLOBAL_CTRL));
	DbgPrint("HOST_IA32_PAT: 0x%x\n", __readmsr(MSR_IA32_CR_PAT));
	DbgPrint("HOST_IA32_PERF_GLOBAL_CTRL: 0x%x\n", __readmsr(MSR_CORE_PERF_GLOBAL_CTRL));

	/* Time-stamp counter offset */
	__vmx_vmwrite(TSC_OFFSET, 0);
	__vmx_vmwrite(TSC_OFFSET_HIGH, 0);

	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

	__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);


	GdtBase = Get_GDT_Base();
	DbgPrint("GUEST registers\n");
	FillGuestSelectorData((PVOID)GdtBase, ES, GetEs());
	FillGuestSelectorData((PVOID)GdtBase, CS, GetCs());
	FillGuestSelectorData((PVOID)GdtBase, SS, GetSs());
	FillGuestSelectorData((PVOID)GdtBase, DS, GetDs());
	FillGuestSelectorData((PVOID)GdtBase, FS, GetFs());
	FillGuestSelectorData((PVOID)GdtBase, GS, GetGs());
	FillGuestSelectorData((PVOID)GdtBase, LDTR, GetLdtr());
	FillGuestSelectorData((PVOID)GdtBase, TR, GetTr());
	DbgPrint("end of GUEST registers\n");

	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));

	DbgPrint("GUEST_FS_BASE: 0x%x\n", __readmsr(MSR_FS_BASE));
	DbgPrint("GUEST_GS_BASE: 0x%x\n", __readmsr(MSR_GS_BASE));

	__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);   //Active state 
	__vmx_vmwrite(VMX_PREEMPTION_TIMER_VALUE, 0);
	__vmx_vmwrite(GUEST_INTR_STATUS, 0);
	__vmx_vmwrite(GUEST_PML_INDEX, 0);

	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_ACTIVATE_MSR_BITMAP, MSR_IA32_VMX_PROCBASED_CTLS));
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP /* | CPU_BASED_CTL2_ENABLE_EPT*/, MSR_IA32_VMX_PROCBASED_CTLS2));
	//__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
	//__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP /* | CPU_BASED_CTL2_ENABLE_EPT*/, MSR_IA32_VMX_PROCBASED_CTLS2));

	DbgPrint("CPU_BASED_VM_EXEC_CONTROL: 0x%x\n", AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_ACTIVATE_MSR_BITMAP, MSR_IA32_VMX_PROCBASED_CTLS));
	DbgPrint("SECONDARY_VM_EXEC_CONTROL: 0x%x\n", AdjustControls(CPU_BASED_CTL2_RDTSCP /* | CPU_BASED_CTL2_ENABLE_EPT*/, MSR_IA32_VMX_PROCBASED_CTLS2));

	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
	//__vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
	//__vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));

	union __vmx_entry_control_t entry_controls = { 0 };
	entry_controls.bits.ia32e_mode_guest = 1;
	vmx_adjust_entry_controls(&entry_controls);
	__vmx_vmwrite(VM_ENTRY_CONTROLS, entry_controls.control);

	union __vmx_exit_control_t exit_controls = { 0 };
	exit_controls.bits.host_address_space_size = 1;
	vmx_adjust_exit_controls(&exit_controls);
	__vmx_vmwrite(VM_EXIT_CONTROLS, exit_controls.control);

	__vmx_vmwrite(CR0_READ_SHADOW, __readcr0());
	__vmx_vmwrite(CR4_READ_SHADOW, __readcr4());

	DbgPrint("PIN_BASED_VM_EXEC_CONTROL: 0x%x\n", AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
	DbgPrint("VM_EXIT_CONTROLS: 0x%x\n", exit_controls.control);
	DbgPrint("VM_ENTRY_CONTROLS: 0x%x\n", entry_controls.control);
	DbgPrint("CR0_READ_SHADOW: 0x%x\n", __readcr0());
	DbgPrint("CR4_READ_SHADOW: 0x%x\n", __readcr4());

	//Exception bitmap - This is a 32 - bit field in which one bit is for each exception.Setting this will define which exception should cause vmexit.We are just going to set it up to 0 to ignore vmexit for any guest exception.
	__vmx_vmwrite(EXCEPTION_BITMAP, 0);

	__vmx_vmwrite(CR3_TARGET_COUNT, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE0, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE1, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE2, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE3, 0);


	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());

	__vmx_vmwrite(GUEST_DR7, 0x400);

	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_CR4, __readcr4());

	DbgPrint("Cr0: 0x%x\n", __readcr0());
	DbgPrint("Cr3: 0x%x\n", __readcr3());
	DbgPrint("Cr4: 0x%x\n", __readcr4());

	__vmx_vmwrite(GUEST_GDTR_BASE, Get_GDT_Base());
	__vmx_vmwrite(GUEST_IDTR_BASE, Get_IDT_Base());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, Get_GDT_Limit());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, Get_IDT_Limit());

	__vmx_vmwrite(GUEST_RFLAGS, Get_RFLAGS());

	DbgPrint("GUEST_GDTR_BASE: 0x%x\n", Get_GDT_Base());
	DbgPrint("GUEST_IDTR_BASE: 0x%x\n", Get_IDT_Base());
	DbgPrint("GUEST_GDTR_LIMIT: 0x%x\n", Get_GDT_Limit());
	DbgPrint("GUEST_IDTR_LIMIT: 0x%x\n", Get_IDT_Limit());
	DbgPrint("GUEST_RFLAGS: 0x%x\n", Get_RFLAGS());

	GetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)Get_GDT_Base());
	__vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

	__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

	__vmx_vmwrite(HOST_GDTR_BASE, Get_GDT_Base());
	__vmx_vmwrite(HOST_IDTR_BASE, Get_IDT_Base());

	DbgPrint("HOST_TR_BASE: 0x%x\n", SegmentSelector.BASE);
	DbgPrint("HOST_FS_BASE: 0x%x\n", __readmsr(MSR_FS_BASE));
	DbgPrint("HOST_GS_BASE: 0x%x\n", __readmsr(MSR_GS_BASE));
	DbgPrint("HOST_GDTR_BASE: 0x%x\n", Get_GDT_Base());
	DbgPrint("HOST_IDTR_BASE: 0x%x\n", Get_IDT_Base());

	//same values for guest and host MSR's
	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

	__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

	DbgPrint("HOST_IA32_SYSENTER_CS: 0x%x\n", __readmsr(MSR_IA32_SYSENTER_CS));
	DbgPrint("HOST_IA32_SYSENTER_EIP: 0x%x\n", __readmsr(MSR_IA32_SYSENTER_EIP));
	DbgPrint("HOST_IA32_SYSENTER_ESP: 0x%x\n", __readmsr(MSR_IA32_SYSENTER_ESP));



	// left here just for test
	UINT64 GUEST_STACK_VA = (UINT64)ExAllocatePoolWithTag(NonPagedPool, 128, POOLTAG);

	__vmx_vmwrite(GUEST_RSP, (ULONG64)GUEST_STACK_VA + 64);     //setup guest sp
	//__vmx_vmwrite(GUEST_RSP, 0);     //setup guest sp
	__vmx_vmwrite(GUEST_RIP, (ULONG64)VirtualGuestMemoryAddress);     //setup guest ip


	__vmx_vmwrite(HOST_RSP, ((ULONG64)vmState->VMM_Stack + VMM_STACK_SIZE - 1));
	__vmx_vmwrite(HOST_RIP, (ULONG64)VMExitHandler);

	DbgPrint("GUEST_RSP: 0x%x\n", (ULONG64)GUEST_STACK_VA + 64);
	DbgPrint("GUEST_RI: 0x%x\n", (ULONG64)VirtualGuestMemoryAddress);
	DbgPrint("HOST_RSP: 0x%x\n", ((ULONG64)vmState->VMM_Stack + VMM_STACK_SIZE - 1));
	DbgPrint("HOST_RIP: 0x%x\n", (ULONG64)VMExitHandler);

	Status = TRUE;
//Exit:
	return Status;
}


VOID ResumeToNextInstruction(VOID)
{
	PVOID ResumeRIP = NULL;
	PVOID CurrentRIP = NULL;
	ULONG ExitInstructionLength = 0;

	__vmx_vmread(GUEST_RIP, &CurrentRIP);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

	ResumeRIP = (PCHAR)CurrentRIP + ExitInstructionLength;

	__vmx_vmwrite(GUEST_RIP, (ULONG64)ResumeRIP);
}

VOID VM_Resumer(VOID)
{

	DbgPrint("We are in VM_Resmuer function\n");
	__vmx_vmresume();

	// if VMRESUME succeed will never be here !

	ULONG64 ErrorCode = 0;
	__vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
	__vmx_off();
	DbgPrint("[*] VMRESUME Error : 0x%llx\n", ErrorCode);

	// It's such a bad error because we don't where to go !
	// prefer to break
	DbgBreakPoint();



}

VOID MainVMExitHandler(PGUEST_REGS GuestRegs)
{
	ULONG ExitReason = 0;
	__vmx_vmread(VM_EXIT_REASON, &ExitReason);


	ULONG ExitQualification = 0;
	__vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);

	DbgPrint("\nVM_EXIT_REASION 0x%x\n", ExitReason & 0xffff);
	DbgPrint("EXIT_QUALIFICATION 0x%x\n", ExitQualification);


	switch (ExitReason)
	{
		//
		// 25.1.2  Instructions That Cause VM Exits Unconditionally
		// The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
		// INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID, 
		// VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
		//

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
		break;
	}
	case EXIT_REASON_HLT:
	{
		DbgPrint("[*] Execution of HLT detected... \n");

		// DbgBreakPoint();

		// that's enough for now ;)
		Restore_To_VMXOFF_State();
		DbgPrint("[*] This will not get printed as ip is changed now \n");
		break;
	}
	case EXIT_REASON_EXCEPTION_NMI:
	{
		break;
	}

	case EXIT_REASON_CPUID:
	{
		break;
	}

	case EXIT_REASON_INVD:
	{
		break;
	}

	case EXIT_REASON_VMCALL:
	{
		break;
	}

	case EXIT_REASON_CR_ACCESS:
	{
		break;
	}

	case EXIT_REASON_MSR_READ:
	{
		break;
	}

	case EXIT_REASON_MSR_WRITE:
	{
		break;
	}

	case EXIT_REASON_EPT_VIOLATION:
	{
		break;
	}

	default:
	{
		DbgBreakPoint();
		break;

	}
	}
}
//debug test
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