#include "Invept_Instruction_Handler.h"
#include "InlineAsm.h"

/* Invoke the Invept instruction */
unsigned char Invept(UINT32 Type, INVEPT_DESC* Descriptor)
{
	if (!Descriptor)
	{
		INVEPT_DESC ZeroDescriptor = { 0 };
		Descriptor = &ZeroDescriptor;
	}

	return AsmInvept(Type, Descriptor);
}

/* Invalidates a single context in ept cache table */
unsigned char Single_Context_Invept(UINT64 EptPointer)
{
	INVEPT_DESC Descriptor = { EptPointer, 0 };
	return Invept(SINGLE_CONTEXT, &Descriptor);
}

/* Invalidates all contexts in ept cache table */
unsigned char All_Contexts_Invept()
{
	return Invept(ALL_CONTEXTS, NULL);
}