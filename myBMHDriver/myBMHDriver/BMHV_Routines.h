#pragma once
#include "Msr.h"
#include "Vmx.h"

/*
   This file contains the headers for Hypervisor Routines which have to be called by external codes,
		DO NOT DIRECTLY CALL VMX FUNCTIONS,
			instead use these routines.
*/

//////////////////////////////////////////////////
//					Functions					//
//////////////////////////////////////////////////

// Detect whether Vmx is supported or not
BOOLEAN BMHV_Check_Vmx_Support();
// Initialize Vmx 
BOOLEAN BMHV_Initialize_VMX();
// Allocates Vmx regions for all logical cores (Vmxon region and Vmcs region)
BOOLEAN Vmx_Dpc_Broadcast_Allocate_Vmxon_Regions(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
// Set Guest Selector Registers
BOOLEAN BMHV_Set_Guest_Selector(PVOID GdtBase, ULONG SegmentRegister, USHORT Selector);
// Get Segment Descriptor
BOOLEAN BMHV_Get_Segment_Descriptor(PSEGMENT_SELECTOR SegmentSelector, USHORT Selector, PUCHAR GdtBase);
// Set Msr Bitmap
BOOLEAN BMHV_Set_Msr_Bitmap(ULONG64 Msr, INT ProcessorID, BOOLEAN ReadDetection, BOOLEAN WriteDetection);

// Returns the Cpu Based and Secondary Processor Based Controls and other controls based on hardware support 
ULONG BMHV_Adjust_Controls(ULONG Ctl, ULONG Msr);

// Notify all cores about EPT Invalidation
VOID BMHV_Notify_All_To_Invalidate_Ept();
// Handle Cpuid
VOID BMHV_Handle_Cpuid_Call(PGUEST_REGS RegistersState);
// Fill guest selector data
VOID BMHV_Fill_Guest_Selector_Data(PVOID GdtBase, ULONG SegmentRegister, USHORT Selector);
// Handle Guest's Control Registers Access
VOID BMHV_Handle_Control_Register_Access(PGUEST_REGS GuestState);
// Handle Guest's Msr read
VOID BMHV_Handle_Msr_Read(PGUEST_REGS GuestRegs);
// Handle Guest's Msr write
VOID BMHV_Handle_Msr_Write(PGUEST_REGS GuestRegs);
// Resume GUEST_RIP to next instruction
VOID BMHV_Resume_To_Next_Instruction();
// Invalidate EPT using Vmcall (should be called from Vmx non root mode)
VOID BMHV_Invalidate_Ept_By_Vmcall(UINT64 Context);
// The broadcast function which initialize the guest
VOID BMHV_Dpc_Broadcast_Initialize_Guest(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
// The broadcast function which terminate the guest
VOID BMHV_Dpc_Broadcast_Terminate_Guest(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
// Terminate Vmx on all logical cores.
VOID BMHV_Terminate_Vmx();

// Returns the stack pointer, to change in the case of Vmxoff 
UINT64 BMHV_Return_Stack_Pointer_For_Vmxoff();
// Returns the instruction pointer, to change in the case of Vmxoff 
UINT64 BMHV_Return_Instruction_Pointer_For_Vmxoff();
VOID BMHV_Set_Monitor_Trap_Flag(BOOLEAN Set);

int digitCount(int N);
void AddToSecretData(PCHAR msgData, int num);