
#pragma once
#include <ntddk.h>
#include "EPT.h"

typedef struct _VirtualMachineState
{
	UINT64 VMXON_REGION;                        // VMXON region
	UINT64 VMCS_REGION;                         // VMCS region
	UINT64 EPTP;								// Extended-Page-Table Pointer
	UINT64 VMM_Stack;							// Stack for VMM in VM-Exit State
	UINT64 MSRBitMap;							// MSRBitMap Virtual Address
	UINT64 MSRBitMapPhysical;					// MSRBitMap Physical Address
} VirtualMachineState, * PVirtualMachineState;

//debug test
#define SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE                        0x00000009
#define SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY                             0x0000000B

union __segment_access_rights_t
{
	struct
	{
		unsigned __int32 type : 4;
		unsigned __int32 descriptor_type : 1;
		unsigned __int32 dpl : 2;
		unsigned __int32 present : 1;
		unsigned __int32 reserved0 : 4;
		unsigned __int32 available : 1;
		unsigned __int32 long_mode : 1;
		unsigned __int32 default_big : 1;
		unsigned __int32 granularity : 1;
		unsigned __int32 unusable : 1;
		unsigned __int32 reserved1 : 15;
	};
	unsigned __int32 flags;
};

union __segment_selector_t
{
	struct
	{
		unsigned __int16 rpl : 2;
		unsigned __int16 table : 1;
		unsigned __int16 index : 13;
	};
	unsigned __int16 flags;
};

struct __segment_descriptor_64_t
{
	unsigned __int16 segment_limit_low;
	unsigned __int16 base_low;
	union
	{
		struct
		{
			unsigned __int32 base_middle : 8;
			unsigned __int32 type : 4;
			unsigned __int32 descriptor_type : 1;
			unsigned __int32 dpl : 2;
			unsigned __int32 present : 1;
			unsigned __int32 segment_limit_high : 4;
			unsigned __int32 system : 1;
			unsigned __int32 long_mode : 1;
			unsigned __int32 default_big : 1;
			unsigned __int32 granularity : 1;
			unsigned __int32 base_high : 8;
		};
		unsigned __int32 flags;
	};
	unsigned __int32 base_upper;
	unsigned __int32 reserved;
};

struct __segment_descriptor_32_t
{
	unsigned __int16 segment_limit_low;
	unsigned __int16 base_low;
	union
	{
		struct
		{
			unsigned __int32 base_middle : 8;
			unsigned __int32 type : 4;
			unsigned __int32 descriptor_type : 1;
			unsigned __int32 dpl : 2;
			unsigned __int32 present : 1;
			unsigned __int32 segment_limit_high : 4;
			unsigned __int32 system : 1;
			unsigned __int32 long_mode : 1;
			unsigned __int32 default_big : 1;
			unsigned __int32 granularity : 1;
			unsigned __int32 base_high : 8;
		};
		unsigned __int32 flags;
	};
};

#pragma pack(push, 1)
struct __pseudo_descriptor_64_t
{
	unsigned __int16 limit;
	unsigned __int64 base_address;
};
#pragma pack(pop)


union __vmx_exit_control_t
{
	unsigned __int64 control;
	struct
	{
		unsigned __int64 reserved_0 : 2;
		unsigned __int64 save_dbg_controls : 1;
		unsigned __int64 reserved_1 : 6;
		unsigned __int64 host_address_space_size : 1;
		unsigned __int64 reserved_2 : 2;
		unsigned __int64 load_ia32_perf_global_control : 1;
		unsigned __int64 reserved_3 : 2;
		unsigned __int64 ack_interrupt_on_exit : 1;
		unsigned __int64 reserved_4 : 2;
		unsigned __int64 save_ia32_pat : 1;
		unsigned __int64 load_ia32_pat : 1;
		unsigned __int64 save_ia32_efer : 1;
		unsigned __int64 load_ia32_efer : 1;
		unsigned __int64 save_vmx_preemption_timer_value : 1;
		unsigned __int64 clear_ia32_bndcfgs : 1;
		unsigned __int64 conceal_vmx_from_pt : 1;
	} bits;
};

union __vmx_entry_control_t
{
	unsigned __int64 control;
	struct
	{
		unsigned __int64 reserved_0 : 2;
		unsigned __int64 load_dbg_controls : 1;
		unsigned __int64 reserved_1 : 6;
		unsigned __int64 ia32e_mode_guest : 1;
		unsigned __int64 entry_to_smm : 1;
		unsigned __int64 deactivate_dual_monitor_treament : 1;
		unsigned __int64 reserved_3 : 1;
		unsigned __int64 load_ia32_perf_global_control : 1;
		unsigned __int64 load_ia32_pat : 1;
		unsigned __int64 load_ia32_efer : 1;
		unsigned __int64 load_ia32_bndcfgs : 1;
		unsigned __int64 conceal_vmx_from_pt : 1;
	} bits;
};

union __vmx_pinbased_control_msr_t
{
	unsigned __int64 control;
	struct
	{
		unsigned __int64 external_interrupt_exiting : 1;
		unsigned __int64 reserved_0 : 2;
		unsigned __int64 nmi_exiting : 1;
		unsigned __int64 reserved_1 : 1;
		unsigned __int64 virtual_nmis : 1;
		unsigned __int64 vmx_preemption_timer : 1;
		unsigned __int64 process_posted_interrupts : 1;
	} bits;
};

union __vmx_primary_processor_based_control_t
{
	unsigned __int64 control;
	struct
	{
		unsigned __int64 reserved_0 : 2;
		unsigned __int64 interrupt_window_exiting : 1;
		unsigned __int64 use_tsc_offsetting : 1;
		unsigned __int64 reserved_1 : 3;
		unsigned __int64 hlt_exiting : 1;
		unsigned __int64 reserved_2 : 1;
		unsigned __int64 invldpg_exiting : 1;
		unsigned __int64 mwait_exiting : 1;
		unsigned __int64 rdpmc_exiting : 1;
		unsigned __int64 rdtsc_exiting : 1;
		unsigned __int64 reserved_3 : 2;
		unsigned __int64 cr3_load_exiting : 1;
		unsigned __int64 cr3_store_exiting : 1;
		unsigned __int64 reserved_4 : 2;
		unsigned __int64 cr8_load_exiting : 1;
		unsigned __int64 cr8_store_exiting : 1;
		unsigned __int64 use_tpr_shadow : 1;
		unsigned __int64 nmi_window_exiting : 1;
		unsigned __int64 mov_dr_exiting : 1;
		unsigned __int64 unconditional_io_exiting : 1;
		unsigned __int64 use_io_bitmaps : 1;
		unsigned __int64 reserved_5 : 1;
		unsigned __int64 monitor_trap_flag : 1;
		unsigned __int64 use_msr_bitmaps : 1;
		unsigned __int64 monitor_exiting : 1;
		unsigned __int64 pause_exiting : 1;
		unsigned __int64 active_secondary_controls : 1;
	} bits;
};

union __vmx_secondary_processor_based_control_t
{
	unsigned __int64 control;
	struct
	{
		unsigned __int64 virtualize_apic_accesses : 1;
		unsigned __int64 enable_ept : 1;
		unsigned __int64 descriptor_table_exiting : 1;
		unsigned __int64 enable_rdtscp : 1;
		unsigned __int64 virtualize_x2apic : 1;
		unsigned __int64 enable_vpid : 1;
		unsigned __int64 wbinvd_exiting : 1;
		unsigned __int64 unrestricted_guest : 1;
		unsigned __int64 apic_register_virtualization : 1;
		unsigned __int64 virtual_interrupt_delivery : 1;
		unsigned __int64 pause_loop_exiting : 1;
		unsigned __int64 rdrand_exiting : 1;
		unsigned __int64 enable_invpcid : 1;
		unsigned __int64 enable_vmfunc : 1;
		unsigned __int64 vmcs_shadowing : 1;
		unsigned __int64 enable_encls_exiting : 1;
		unsigned __int64 rdseed_exiting : 1;
		unsigned __int64 enable_pml : 1;
		unsigned __int64 use_virtualization_exception : 1;
		unsigned __int64 conceal_vmx_from_pt : 1;
		unsigned __int64 enable_xsave_xrstor : 1;
		unsigned __int64 reserved_0 : 1;
		unsigned __int64 mode_based_execute_control_ept : 1;
		unsigned __int64 reserved_1 : 2;
		unsigned __int64 use_tsc_scaling : 1;
	} bits;
};

// PIN-Based Execution
#define PIN_BASED_VM_EXECUTION_CONTROLS_EXTERNAL_INTERRUPT        0x00000001
#define PIN_BASED_VM_EXECUTION_CONTROLS_NMI_EXITING               0x00000008
#define PIN_BASED_VM_EXECUTION_CONTROLS_VIRTUAL_NMI               0x00000020
#define PIN_BASED_VM_EXECUTION_CONTROLS_ACTIVE_VMX_TIMER          0x00000040
#define PIN_BASED_VM_EXECUTION_CONTROLS_PROCESS_POSTED_INTERRUPTS 0x00000080


#define CPU_BASED_VIRTUAL_INTR_PENDING        0x00000004
#define CPU_BASED_USE_TSC_OFFSETING           0x00000008
#define CPU_BASED_HLT_EXITING                 0x00000080
#define CPU_BASED_INVLPG_EXITING              0x00000200
#define CPU_BASED_MWAIT_EXITING               0x00000400
#define CPU_BASED_RDPMC_EXITING               0x00000800
#define CPU_BASED_RDTSC_EXITING               0x00001000
#define CPU_BASED_CR3_LOAD_EXITING            0x00008000
#define CPU_BASED_CR3_STORE_EXITING           0x00010000
#define CPU_BASED_CR8_LOAD_EXITING            0x00080000
#define CPU_BASED_CR8_STORE_EXITING           0x00100000
#define CPU_BASED_TPR_SHADOW                  0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING         0x00400000
#define CPU_BASED_MOV_DR_EXITING              0x00800000
#define CPU_BASED_UNCOND_IO_EXITING           0x01000000
#define CPU_BASED_ACTIVATE_IO_BITMAP          0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG           0x08000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP         0x10000000
#define CPU_BASED_MONITOR_EXITING             0x20000000
#define CPU_BASED_PAUSE_EXITING               0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS 0x80000000

#define CPU_BASED_CTL2_ENABLE_EPT			0x2
#define CPU_BASED_CTL2_RDTSCP				0x8
#define CPU_BASED_CTL2_ENABLE_VPID			0x20
#define CPU_BASED_CTL2_UNRESTRICTED_GUEST	0x80
#define CPU_BASED_CTL2_ENABLE_VMFUNC		0x2000


// VM-exit Control Bits 
#define VM_EXIT_IA32E_MODE              0x00000200
#define VM_EXIT_ACK_INTR_ON_EXIT        0x00008000
#define VM_EXIT_SAVE_GUEST_PAT          0x00040000
#define VM_EXIT_LOAD_HOST_PAT           0x00080000
#define VM_EXIT_HOST_ADDR_SPACE_SIZE	0x00000200




// VM-entry Control Bits 
#define VM_ENTRY_IA32E_MODE             0x00000200
#define VM_ENTRY_SMM                    0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR     0x00000800
#define VM_ENTRY_LOAD_GUEST_PAT         0x00004000


enum VMCS_FIELDS {
	GUEST_ES_SELECTOR = 0x00000800,
	GUEST_CS_SELECTOR = 0x00000802,
	GUEST_SS_SELECTOR = 0x00000804,
	GUEST_DS_SELECTOR = 0x00000806,
	GUEST_FS_SELECTOR = 0x00000808,
	GUEST_GS_SELECTOR = 0x0000080a,
	GUEST_LDTR_SELECTOR = 0x0000080c,
	GUEST_TR_SELECTOR = 0x0000080e,
	HOST_ES_SELECTOR = 0x00000c00,
	HOST_CS_SELECTOR = 0x00000c02,
	HOST_SS_SELECTOR = 0x00000c04,
	HOST_DS_SELECTOR = 0x00000c06,
	HOST_FS_SELECTOR = 0x00000c08,
	HOST_GS_SELECTOR = 0x00000c0a,
	HOST_TR_SELECTOR = 0x00000c0c,
	IO_BITMAP_A = 0x00002000,
	IO_BITMAP_A_HIGH = 0x00002001,
	IO_BITMAP_B = 0x00002002,
	IO_BITMAP_B_HIGH = 0x00002003,
	MSR_BITMAP = 0x00002004,
	MSR_BITMAP_HIGH = 0x00002005,
	VM_EXIT_MSR_STORE_ADDR = 0x00002006,
	VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
	VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
	VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
	VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
	VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
	TSC_OFFSET = 0x00002010,
	TSC_OFFSET_HIGH = 0x00002011,
	VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
	VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
	VMFUNC_CONTROLS = 0x00002018,
	VMFUNC_CONTROLS_HIGH = 0x00002019,
	EPT_POINTER = 0x0000201A,
	EPT_POINTER_HIGH = 0x0000201B,
	EPTP_LIST = 0x00002024,
	EPTP_LIST_HIGH = 0x00002025,
	GUEST_PHYSICAL_ADDRESS = 0x2400,
	GUEST_PHYSICAL_ADDRESS_HIGH = 0x2401,
	VMCS_LINK_POINTER = 0x00002800,
	VMCS_LINK_POINTER_HIGH = 0x00002801,
	GUEST_IA32_DEBUGCTL = 0x00002802,
	GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
	PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
	CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
	EXCEPTION_BITMAP = 0x00004004,
	PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
	PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
	CR3_TARGET_COUNT = 0x0000400a,
	VM_EXIT_CONTROLS = 0x0000400c,
	VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
	VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
	VM_ENTRY_CONTROLS = 0x00004012,
	VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
	VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
	VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
	VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
	TPR_THRESHOLD = 0x0000401c,
	SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
	VM_INSTRUCTION_ERROR = 0x00004400,
	VM_EXIT_REASON = 0x00004402,
	VM_EXIT_INTR_INFO = 0x00004404,
	VM_EXIT_INTR_ERROR_CODE = 0x00004406,
	IDT_VECTORING_INFO_FIELD = 0x00004408,
	IDT_VECTORING_ERROR_CODE = 0x0000440a,
	VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
	VMX_INSTRUCTION_INFO = 0x0000440e,
	GUEST_ES_LIMIT = 0x00004800,
	GUEST_CS_LIMIT = 0x00004802,
	GUEST_SS_LIMIT = 0x00004804,
	GUEST_DS_LIMIT = 0x00004806,
	GUEST_FS_LIMIT = 0x00004808,
	GUEST_GS_LIMIT = 0x0000480a,
	GUEST_LDTR_LIMIT = 0x0000480c,
	GUEST_TR_LIMIT = 0x0000480e,
	GUEST_GDTR_LIMIT = 0x00004810,
	GUEST_IDTR_LIMIT = 0x00004812,
	GUEST_ES_AR_BYTES = 0x00004814,
	GUEST_CS_AR_BYTES = 0x00004816,
	GUEST_SS_AR_BYTES = 0x00004818,
	GUEST_DS_AR_BYTES = 0x0000481a,
	GUEST_FS_AR_BYTES = 0x0000481c,
	GUEST_GS_AR_BYTES = 0x0000481e,
	GUEST_LDTR_AR_BYTES = 0x00004820,
	GUEST_TR_AR_BYTES = 0x00004822,
	GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
	GUEST_ACTIVITY_STATE = 0x00004826,
	GUEST_SM_BASE = 0x00004828,
	GUEST_SYSENTER_CS = 0x0000482A,
	HOST_IA32_SYSENTER_CS = 0x00004c00,
	CR0_GUEST_HOST_MASK = 0x00006000,
	CR4_GUEST_HOST_MASK = 0x00006002,
	CR0_READ_SHADOW = 0x00006004,
	CR4_READ_SHADOW = 0x00006006,
	CR3_TARGET_VALUE0 = 0x00006008,
	CR3_TARGET_VALUE1 = 0x0000600a,
	CR3_TARGET_VALUE2 = 0x0000600c,
	CR3_TARGET_VALUE3 = 0x0000600e,
	EXIT_QUALIFICATION = 0x00006400,
	GUEST_LINEAR_ADDRESS = 0x0000640a,
	GUEST_CR0 = 0x00006800,
	GUEST_CR3 = 0x00006802,
	GUEST_CR4 = 0x00006804,
	GUEST_ES_BASE = 0x00006806,
	GUEST_CS_BASE = 0x00006808,
	GUEST_SS_BASE = 0x0000680a,
	GUEST_DS_BASE = 0x0000680c,
	GUEST_FS_BASE = 0x0000680e,
	GUEST_GS_BASE = 0x00006810,
	GUEST_LDTR_BASE = 0x00006812,
	GUEST_TR_BASE = 0x00006814,
	GUEST_GDTR_BASE = 0x00006816,
	GUEST_IDTR_BASE = 0x00006818,
	GUEST_DR7 = 0x0000681a,
	GUEST_RSP = 0x0000681c,
	GUEST_RIP = 0x0000681e,
	GUEST_RFLAGS = 0x00006820,
	GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
	GUEST_SYSENTER_ESP = 0x00006824,
	GUEST_SYSENTER_EIP = 0x00006826,
	HOST_CR0 = 0x00006c00,
	HOST_CR3 = 0x00006c02,
	HOST_CR4 = 0x00006c04,
	HOST_FS_BASE = 0x00006c06,
	HOST_GS_BASE = 0x00006c08,
	HOST_TR_BASE = 0x00006c0a,
	HOST_GDTR_BASE = 0x00006c0c,
	HOST_IDTR_BASE = 0x00006c0e,
	HOST_IA32_SYSENTER_ESP = 0x00006c10,
	HOST_IA32_SYSENTER_EIP = 0x00006c12,
	HOST_RSP = 0x00006c14,
	HOST_RIP = 0x00006c16,

	VMX_PREEMPTION_TIMER_VALUE	=	0x0000482E,
	GUEST_INTR_STATUS			=	0x00000810,
	GUEST_PML_INDEX				=	0x00000812,

	GUEST_IA32_PAT				=	0x00002804,
	GUEST_IA32_EFER				=	0x00002806,
	GUEST_IA32_PERF_GLOBAL_CTRL	=	0x00002808,

	HOST_IA32_PAT				=	0x00002c00,
	HOST_IA32_EFER				=	0x00002c02,
	HOST_IA32_PERF_GLOBAL_CTRL	=	0x00002c04,
};


#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT                3
#define EXIT_REASON_SIPI                4
#define EXIT_REASON_IO_SMI              5
#define EXIT_REASON_OTHER_SMI           6
#define EXIT_REASON_PENDING_VIRT_INTR   7
#define EXIT_REASON_PENDING_VIRT_NMI    8
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_GETSEC              11
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_RSM                 17
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMXOFF              26
#define EXIT_REASON_VMXON               27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_GUEST_STATE 33
#define EXIT_REASON_MSR_LOADING         34
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_TRAP_FLAG   37
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_MCE_DURING_VMENTRY  41
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define EXIT_REASON_APIC_ACCESS         44
#define EXIT_REASON_ACCESS_GDTR_OR_IDTR 46
#define EXIT_REASON_ACCESS_LDTR_OR_TR   47
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_INVEPT              50
#define EXIT_REASON_RDTSCP              51
#define EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED     52
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55
#define EXIT_REASON_APIC_WRITE          56
#define EXIT_REASON_RDRAND              57
#define EXIT_REASON_INVPCID             58
#define EXIT_REASON_RDSEED              61
#define EXIT_REASON_PML_FULL            62
#define EXIT_REASON_XSAVES              63
#define EXIT_REASON_XRSTORS             64
#define EXIT_REASON_PCOMMIT             65


extern PVirtualMachineState vmState;

extern UINT64 VirtualGuestMemoryAddress;

extern int ProcessorCounts;

#define POOLTAG 0x48564653 // [H]yper[V]isor [F]rom [S]cratch (HVFS)
#define VMM_STACK_SIZE      0x8000
#define RPL_MASK                3

ULONG ExitReason;

void Initiate_VMX(void);
void Terminate_VMX(void);
UINT64 VirtualAddress_to_PhysicalAddress(void* va);
PVOID PhysicalAddress_to_VirtualAddress(UINT64 pa);
BOOLEAN Allocate_VMXON_Region(IN PVirtualMachineState vmState);
BOOLEAN Allocate_VMCS_Region(IN PVirtualMachineState vmState);
UINT64 VMPTRST(void);
void Run_On_Each_Logical_Processor(void* (*FunctionPtr)());
int ipow(int base, int exp);
void Inline_Memory_Patcher(void);
extern ULONG64 inline Get_GDT_Base(void);
extern ULONG64 inline Get_IDT_Base(void);
extern void inline Enable_VMX_Operation(void);
extern void inline  Restore_To_VMXOFF_State();
extern void inline  Save_VMXOFF_State();
extern unsigned char inline INVEPT_Instruction(_In_ unsigned long type, _In_ void* descriptor);
BOOLEAN Is_VMX_Supported();
VOID VMExitHandler(VOID);
void LaunchVM(int ProcessorID, PEPTP EPTP);
BOOLEAN Setup_VMCS(IN PVirtualMachineState vmState, IN PEPTP EPTP);
BOOLEAN Load_VMCS(IN PVirtualMachineState vmState);
BOOLEAN Clear_VMCS_State(IN PVirtualMachineState vmState);
VOID VM_Resumer(VOID);
static unsigned __int64 vmx_adjust_cv(unsigned int capability_msr, unsigned __int64 value);
void vmx_adjust_pinbased_controls(union __vmx_pinbased_control_msr_t* exit_controls);
static void vmx_adjust_exit_controls(union __vmx_exit_control_t* exit_controls);
static void vmx_adjust_entry_controls(union __vmx_entry_control_t* entry_controls);
static unsigned __int64 get_segment_base(unsigned __int64 gdt_base, unsigned __int16 segment_selector);
static unsigned __int32 read_segment_access_rights(unsigned __int16 segment_selector);