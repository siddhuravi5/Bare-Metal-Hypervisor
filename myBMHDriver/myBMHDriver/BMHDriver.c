#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "BMHDriver_CPU.h"
#include "MSR.h"
#include "VMX.h"


NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	UINT64 uiIndex = 0;
	PDEVICE_OBJECT pDeviceObject = NULL;

	//the lowercase prefix represnts the type, us - unicode_string
	UNICODE_STRING usDriverName, usDosDeviceName;

	DbgPrint("My BMH Driver Entry Called\n");

	RtlInitUnicodeString(&usDriverName, L"\\Device\\MyBMHDevice");

	//DosDevices is for symbolic links for the devices
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\MyBMHDevice");

	NtStatus = IoCreateDevice(pDriverObject, 0, &usDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);



	if (NtStatus!= STATUS_SUCCESS)
	{
		DbgPrint("Error creating the device.\n");
		return NtStatus;
	}

	for (uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++) {
		pDriverObject->MajorFunction[uiIndex] = UnsupportedDriver;
	}

	DbgPrint("Setting the major functions for our BMH driver\n");

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateDriver;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseDriver;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = WriteDriver;
	pDriverObject->MajorFunction[IRP_MJ_READ] = ReadDriver;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOCTLDispatcherDriver;

	pDriverObject->DriverUnload = UnloadDriver;
	IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);

	__try
	{

		// Initiating EPTP and VMX
		PEPTP EPTP = EPTP_Initialize();
		VMX_Initiate();

		//create guest code, our guest VM
		//it was 100*
		//10 is the number of pages
		for (size_t i = 0; i < (10 * PAGE_SIZE) - 1; i++)
		{
			void* TempAsm = "\xF4";
			memcpy((void *)(VirtualGuestMemoryAddress + i), TempAsm, 1);

		}
		// Launching VM for Test (in the 0th virtual processor)
		int ProcessorID = 0;

		VM_Launch(ProcessorID, EPTP);
		DbgPrint("Guest VM Launched and exited successfully\n");

	}
	__except (GetExceptionCode())
	{

	}
	return NtStatus;
}

VOID UnloadDriver(PDRIVER_OBJECT  DriverObject)
{
	UNICODE_STRING usDosDeviceName;
	DbgPrint("Unloading the driver\n");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\MyBMHDevice");
	IoDeleteSymbolicLink(&usDosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);

}

NTSTATUS CreateDriver(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{

	DbgPrint("Create Driver\n");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS ReadDriver(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("Not implemented yet\n");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS WriteDriver(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("Not implemented yet :( ! \n");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS CloseDriver(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("Drviver Close Called ! \n");

	// executing VMXOFF on every logical processor
	VMX_Terminate();

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS UnsupportedDriver(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("This function is not supported :( ! \n");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS IOCTLDispatcherDriver(PDEVICE_OBJECT DeviceObject, PIRP Irp)

/*++
Routine Description:
	This routine is called by the I/O system to perform a device I/O
	control function.
Arguments:
	DeviceObject - a pointer to the object that represents the device
		that I/O is to be done on.
	Irp - a pointer to the I/O Request Packet for this request.
Return Value:
	NT status code
--*/

{
	PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
	NTSTATUS            ntStatus = STATUS_SUCCESS;// Assume success
	ULONG               inBufLength; // Input buffer length
	ULONG               outBufLength; // Output buffer length
	PVOID               inBuf, outBuf; // pointer to Input and output buffer
	WCHAR*              data = L"Hi, this is a message from the Device Driver.";
	PCHAR				sentData = "Hi, this is a message from the Device Driver.";
	size_t              datalen = 120;
	//size_t              datalen = strlen(data) + 1;//Length of data including null
	PMDL                mdl = NULL;
	PVOID               buffer = NULL;

	UNREFERENCED_PARAMETER(DeviceObject);

	PAGED_CODE();

	irpSp = IoGetCurrentIrpStackLocation(Irp);
	inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (!inBufLength || !outBufLength)
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		goto End;
	}

	//
	// Determine which I/O control code was specified.
	//

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_METHOD_BUFFERED:

		DbgPrint("\nUsing IOCTL METHOD_BUFFERED transfer type\n");
		PrintIrpInfo(Irp);

		//
		// Input buffer and output buffer is same in this case, read the
		// content of the buffer before writing to it
		//

		inBuf = Irp->AssociatedIrp.SystemBuffer;
		outBuf = Irp->AssociatedIrp.SystemBuffer;

		//
		// Read the data from the buffer
		//

		DbgPrint("\tData received from User : ");
		//
		// We are using the following function to print characters instead
		// DebugPrint with %s format because we string we get may or
		// may not be null terminated.
		//
		DbgPrint(inBuf);
		DbgPrint("\n");
		//PrintChars(inBuf, inBufLength);

		//
		// Write to the buffer over-writes the input buffer content
		//

		RtlCopyBytes(outBuf, data, outBufLength);
		//wcsncpy(outBuf, data, outBufLength);
		DbgPrint(("\tData sent to User : "));
		DbgPrint(sentData);
		DbgPrint("\n");

		//
		// Assign the length of the data copied to IoStatus.Information
		// of the Irp and complete the Irp.
		//

		Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);

		//
		// When the Irp is completed the content of the SystemBuffer
		// is copied to the User output buffer and the SystemBuffer is
		// is freed.
		//

		break;
	case IOCTL_METHOD_IN_DIRECT:

		//
		// In this type of transfer,  the I/O manager allocates a system buffer
		// large enough to accommodatethe User input buffer, sets the buffer address
		// in Irp->AssociatedIrp.SystemBuffer and copies the content of user input buffer
		// into the SystemBuffer. For the user output buffer, the  I/O manager
		// probes to see whether the virtual address is readable in the callers
		// access mode, locks the pages in memory and passes the pointer to
		// MDL describing the buffer in Irp->MdlAddress.
		//

		DbgPrint("\nUsing IOCTL METHOD_IN_DIRECT transfer type\n\n");

		PrintIrpInfo(Irp);

		inBuf = Irp->AssociatedIrp.SystemBuffer;

		DbgPrint("\tData from User : ");
		DbgPrint(inBuf);
		DbgPrint("\n");
		//PrintChars(inBuf, inBufLength);

		//
		// To access the output buffer, just get the system address
		// for the buffer. For this method, this buffer is intended for transfering data
		// from the application to the driver.
		//

		buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);

		if (!buffer) {
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}


		Irp->IoStatus.Information = MmGetMdlByteCount(Irp->MdlAddress);

		//
		// NOTE: Changes made to the  SystemBuffer are not copied
		// to the user input buffer by the I/O manager
		//

		break;

	case IOCTL_METHOD_OUT_DIRECT:

		//
		// In this type of transfer, the I/O manager allocates a system buffer
		// large enough to accommodate the User input buffer, sets the buffer address
		// in Irp->AssociatedIrp.SystemBuffer and copies the content of user input buffer
		// into the SystemBuffer. For the output buffer, the I/O manager
		// probes to see whether the virtual address is writable in the callers
		// access mode, locks the pages in memory and passes the pointer to MDL
		// describing the buffer in Irp->MdlAddress.
		//


		DbgPrint("\nUsing IOCTL METHOD_OUT_DIRECT transfer type\n");

		PrintIrpInfo(Irp);

		inBuf = Irp->AssociatedIrp.SystemBuffer;

		//
		// To access the output buffer, just get the system address
		// for the buffer. For this method, this buffer is intended for transfering data
		// from the driver to the application.
		//

		buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);

		if (!buffer) {
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		//
		// Write data to be sent to the user in this buffer
		//

		RtlCopyBytes(buffer, data, outBufLength);

		DbgPrint("\tData sent to User : ");
		//PrintChars(buffer, datalen);
		DbgPrint(sentData);
		DbgPrint("\n");
		Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);

		//
		// NOTE: Changes made to the  SystemBuffer are not copied
		// to the user input buffer by the I/O manager
		//

		break;

	case IOCTL_METHOD_NEITHER:

			//
			// In this type of transfer the I/O manager assigns the user input
			// to Type3InputBuffer and the output buffer to UserBuffer of the Irp.
			// The I/O manager doesn't copy or map the buffers to the kernel
			// buffers. Nor does it perform any validation of user buffer's address
			// range.
			//


			DbgPrint("\nUsing IOCTL METHOD_NEITHER transfer type\n");

			PrintIrpInfo(Irp);

			//
			// A driver may access these buffers directly if it is a highest level
			// driver whose Dispatch routine runs in the context
			// of the thread that made this request. The driver should always
			// check the validity of the user buffer's address range and check whether
			// the appropriate read or write access is permitted on the buffer.
			// It must also wrap its accesses to the buffer's address range within
			// an exception handler in case another user thread deallocates the buffer
			// or attempts to change the access rights for the buffer while the driver
			// is accessing memory.
			//

			inBuf = irpSp->Parameters.DeviceIoControl.Type3InputBuffer;
			outBuf = Irp->UserBuffer;

			//
			// Access the buffers directly if only if you are running in the
			// context of the calling process. Only top level drivers are
			// guaranteed to have the context of process that made the request.
			//

			try {
				//
				// Before accessing user buffer, you must probe for read/write
				// to make sure the buffer is indeed an userbuffer with proper access
				// rights and length. ProbeForRead/Write will raise an exception if it's otherwise.
				//
				ProbeForRead(inBuf, inBufLength, sizeof(UCHAR));

				//
				// Since the buffer access rights can be changed or buffer can be freed
				// anytime by another thread of the same process, you must always access
				// it within an exception handler.
				//

				DbgPrint("\tData from User :");
				DbgPrint(inBuf);
				DbgPrint("\n");
				//PrintChars(inBuf, inBufLength);

			}
			except(EXCEPTION_EXECUTE_HANDLER)
			{

				ntStatus = GetExceptionCode();
				DbgPrint(
					"Exception while accessing inBuf 0X%08X in METHOD_NEITHER\n",
					ntStatus);
				break;
			}


			//
			// If you are accessing these buffers in an arbitrary thread context,
			// say in your DPC or ISR, if you are using it for DMA, or passing these buffers to the
			// next level driver, you should map them in the system process address space.
			// First allocate an MDL large enough to describe the buffer
			// and initilize it. Please note that on a x86 system, the maximum size of a buffer
			// that an MDL can describe is 65508 KB.
			//

			mdl = IoAllocateMdl(inBuf, inBufLength, FALSE, TRUE, NULL);
			if (!mdl)
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			try
			{

				//
				// Probe and lock the pages of this buffer in physical memory.
				// You can specify IoReadAccess, IoWriteAccess or IoModifyAccess
				// Always perform this operation in a try except block.
				//  MmProbeAndLockPages will raise an exception if it fails.
				//
				MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
			}
			except(EXCEPTION_EXECUTE_HANDLER)
			{

				ntStatus = GetExceptionCode();
				//DbgPrint(("Exception while locking inBuf 0X%08X in METHOD_NEITHER\n",ntStatus));
				IoFreeMdl(mdl);
				break;
			}

			//
			// Map the physical pages described by the MDL into system space.
			// Note: double mapping the buffer this way causes lot of
			// system overhead for large size buffers.
			//

			buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);

			if (!buffer) {
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				MmUnlockPages(mdl);
				IoFreeMdl(mdl);
				break;
			}

			//
			// Now you can safely read the data from the buffer.
			//
			
			//DbgPrint("\tData from User (SystemAddress) : ");
			//DbgPrint(buffer);
			
			//PrintChars(buffer, inBufLength);

			//
			// Once the read is over unmap and unlock the pages.
			//

			MmUnlockPages(mdl);
			IoFreeMdl(mdl);

			//
			// The same steps can be followed to access the output buffer.
			//

			mdl = IoAllocateMdl(outBuf, outBufLength, FALSE, TRUE, NULL);
			if (!mdl)
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}


			try {
				//
				// Probe and lock the pages of this buffer in physical memory.
				// You can specify IoReadAccess, IoWriteAccess or IoModifyAccess.
				//

				MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
			}
			except(EXCEPTION_EXECUTE_HANDLER)
			{

				ntStatus = GetExceptionCode();
				DbgPrint(
					"Exception while locking outBuf 0X%08X in METHOD_NEITHER\n",
					ntStatus);
				IoFreeMdl(mdl);
				break;
			}


			buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);

			if (!buffer) {
				MmUnlockPages(mdl);
				IoFreeMdl(mdl);
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			//
			// Write to the buffer
			//

			RtlCopyBytes(buffer, data, outBufLength);

			DbgPrint("\tData sent to User : ");
			DbgPrint(sentData);
			DbgPrint("\n");
			//PrintChars(buffer, datalen);

			MmUnlockPages(mdl);

			//
			// Free the allocated MDL
			//

			IoFreeMdl(mdl);

			//
			// Assign the length of the data copied to IoStatus.Information
			// of the Irp and complete the Irp.
			//

			Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);

			break;

	default:

		//
		// The specified I/O control code is unrecognized by this driver.
		//

		ntStatus = STATUS_INVALID_DEVICE_REQUEST;
		DbgPrint("ERROR: unrecognized IOCTL %x\n",
			irpSp->Parameters.DeviceIoControl.IoControlCode);
		break;
	}

End:
	//
	// Finish the I/O operation by simply completing the packet and returning
	// the same status as in the packet itself.
	//

	Irp->IoStatus.Status = ntStatus;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntStatus;
}



VOID PrintIrpInfo(PIRP Irp)
{
	PIO_STACK_LOCATION  irpSp;
	irpSp = IoGetCurrentIrpStackLocation(Irp);

	PAGED_CODE();

	DbgPrint("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
		Irp->AssociatedIrp.SystemBuffer);
	DbgPrint("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer);
	DbgPrint("\tirpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
		irpSp->Parameters.DeviceIoControl.Type3InputBuffer);
	DbgPrint("\tirpSp->Parameters.DeviceIoControl.InputBufferLength = %d\n",
		irpSp->Parameters.DeviceIoControl.InputBufferLength);
	DbgPrint("\tirpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
		irpSp->Parameters.DeviceIoControl.OutputBufferLength);
	DbgPrint("\n");
	return;
}
