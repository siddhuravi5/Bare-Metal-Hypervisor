#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "MSR.h"
#include "BMHDriver_CPU.h"


int power(int base, int exp) {
	int ans = 1;
	for (int i = 0; i < exp; i++) {
		ans = ans * base;
	}
	return ans;
}

void printCurrentExecutingLogicalProcessor(int i)
{
	char temp[2] = { 't','h' };
	if (i == 1) {
		temp[0] = 's';
		temp[1] = 't';
	}
	else if (i == 2) {
		temp[0] = 'n';
		temp[1] = 'd';
	}
	else if (i == 3) {
		temp[0] = 'r';
		temp[1] = 'd';
	}
	DbgPrint("Current thread is executing in %d %c%c logical processor\n.", i, temp[0], temp[1]);
}
void Run_On_Each_Logical_Processor(void* (*FunctionPtr)()) {

	KAFFINITY kAffinityMask;
	for (int i = 0; i < KeQueryActiveProcessors(); i++)
	{
		kAffinityMask = power(2, i);
		KeSetSystemAffinityThread(kAffinityMask);
		// do st here !
		DbgPrint("=====================================================\n");
		printCurrentExecutingLogicalProcessor(i);
		FunctionPtr();
	}

}


BOOLEAN Check_VMX_Support()
{
	CPUID data = { 0 };

	// VMX bit
	__cpuid((int*)&data, 1);
	if ((data.ecx & (1 << 5)) == 0)
		return FALSE;

	IA32_FEATURE_CONTROL_MSR Control = { 0 };
	Control.All = __readmsr(MSR_IA32_FEATURE_CONTROL);

	// BIOS lock check
	if (Control.Fields.Lock == 0)
	{
		Control.Fields.Lock = TRUE;
		Control.Fields.EnableVmxon = TRUE;
		__writemsr(MSR_IA32_FEATURE_CONTROL, Control.All);
	}
	else if (Control.Fields.EnableVmxon == FALSE)
	{
		DbgPrint("VMX is locked off in BIOS\n");
		return FALSE;
	}

	return TRUE;
}