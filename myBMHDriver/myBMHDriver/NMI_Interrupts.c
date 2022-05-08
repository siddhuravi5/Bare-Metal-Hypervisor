#include "NMI_Interrupts.h"
#include "Vmx.h"



// Injects interruption to a guest
VOID Event_Inject_Interruption(INTERRUPT_TYPE InterruptionType, EXCEPTION_VECTORS Vector, BOOLEAN DeliverErrorCode, ULONG32 ErrorCode)
{
	INTERRUPT_INFO Inject = { 0 };
	Inject.Valid = TRUE;
	Inject.InterruptType = InterruptionType;
	Inject.Vector = Vector;
	Inject.DeliverCode = DeliverErrorCode;
	__vmx_vmwrite(VM_ENTRY_INTR_INFO, Inject.Flags);

	if (DeliverErrorCode) {
		__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, ErrorCode);
	}
}

/* Inject #BP to the guest (Event Injection) */
VOID Event_Inject_Break_point()
{
	Event_Inject_Interruption(INTERRUPT_TYPE_SOFTWARE_EXCEPTION, EXCEPTION_VECTOR_BREAKPOINT, FALSE, 0);
	UINT32 ExitInstrLength;
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstrLength);
	__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, ExitInstrLength);
}

/* Inject #Divide By Zero to the guest (Event Injection) */
VOID Event_Inject_Divide_By_Zero()
{
	Event_Inject_Interruption(INTERRUPT_TYPE_HARDWARE_EXCEPTION, EXCEPTION_DIVIDED_BY_ZERO, FALSE, 0);
	UINT32 ExitInstrLength;
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstrLength);
	__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, ExitInstrLength);
}


/* Inject #GP to the guest (Event Injection) */
VOID Event_Inject_General_Protection()
{
	Event_Inject_Interruption(INTERRUPT_TYPE_HARDWARE_EXCEPTION, EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, TRUE, 0);
	UINT32 ExitInstrLength;
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstrLength);
	__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, ExitInstrLength);
}


/* Inject #UD to the guest (Invalid Opcode - Undefined Opcode) */
VOID Event_Inject_Undefined_Opcode()
{
	Event_Inject_Interruption(INTERRUPT_TYPE_HARDWARE_EXCEPTION, EXCEPTION_VECTOR_UNDEFINED_OPCODE, FALSE, 0);
}
