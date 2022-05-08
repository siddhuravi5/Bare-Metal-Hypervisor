#include "Vmcall_Handler.h"
#include "Global_Variables.h"
#include "Helper.h"
#include "Invept_Instruction_Handler.h"
#include "BMHV_Routines.h"

/*VMCALL instruction causes VM Exit, and passes control to the hypervisor*/
/* Main Vmcall Handler */
NTSTATUS VMCALL_Handler_For_VMX(UINT64 VmcallNumber, UINT64 OptionalParam1, UINT64 OptionalParam2, UINT64 OptionalParam3)
{
	NTSTATUS VmcallStatus;
	BOOLEAN HookResult;


	VmcallStatus = STATUS_UNSUCCESSFUL;
	switch (VmcallNumber)
	{
	case VMCALL_TEST:
	{
		AddToSecretData("VM CALL for testing", -1);
		VmcallStatus = Test_Fn_For_VMCALL(OptionalParam1, OptionalParam2, OptionalParam3);
		break;
	}
	case VMCALL_VMXOFF:
	{
		AddToSecretData("VM CALL for executing VMXOFF", -1);
		Vmx_Vmxoff();
		VmcallStatus = STATUS_SUCCESS;
		break;
	}
	case VMCALL_EXEC_HOOK_PAGE:
	{
		AddToSecretData("VM CALL for Exec Hook Page", -1);
		HookResult = EptVmxRootModePageHook(OptionalParam1, TRUE);

		if (HookResult)
		{
			VmcallStatus = STATUS_SUCCESS;
		}
		else
		{
			VmcallStatus = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case VMCALL_INVEPT_SINGLE_CONTEXT:
	{
		AddToSecretData("VM CALL for Invept Single Context", -1);
		Single_Context_Invept(OptionalParam1);
		VmcallStatus = STATUS_SUCCESS;
		break;
	}
	case VMCALL_INVEPT_ALL_CONTEXT:
	{
		AddToSecretData("VM CALL for Invept All Context", -1);
		All_Contexts_Invept();
		VmcallStatus = STATUS_SUCCESS;
		break;
	}
	default:
	{
		LogWarning("Unsupported VMCALL");
		VmcallStatus = STATUS_UNSUCCESSFUL;
		break;
	}

	}
	AddToSecretData("Param 1 :", OptionalParam1);
	AddToSecretData("Param 2 :", OptionalParam2);
	AddToSecretData("Param 3 :", OptionalParam3);
	return VmcallStatus;
}

/* Test Vmcall (VMCALL_TEST) */
NTSTATUS Test_Fn_For_VMCALL(UINT64 Param1, UINT64 Param2, UINT64 Param3) {

	LogInfo("VMCALL was called with param1 = 0x%lx , Param2 = 0x%lx , Param3 = 0x%lx", Param1, Param2, Param3);
	return STATUS_SUCCESS;
}