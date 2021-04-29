//#include <wdm.h>
#include <ntddk.h>

#define BUFFERSIZE 5

typedef struct _REGISTER_EVENT
{
	HANDLE  hEvent;
	char EventParameter[BUFFERSIZE];

} REGISTER_EVENT, * PREGISTER_EVENT;

REGISTER_EVENT* driverExtension = NULL;

/* Function Prototypes */
NTSTATUS MyDriver_UnSupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID MyDriver_Unload(PDRIVER_OBJECT  DriverObject);
NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath);
NTSTATUS DispatchCreate(PDEVICE_OBJECT    pDevObj, PIRP pIrp);
NTSTATUS DispatchClose(IN PDEVICE_OBJECT    pDevObj, IN PIRP pIrp);
NTSTATUS DispatchRead(PDEVICE_OBJECT    pDevObj, PIRP pIrp);
NTSTATUS DispatchWrite(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS DeviceIoEvent(IN PDEVICE_OBJECT    pDevObj, IN PIRP pIrp);

#pragma warning( disable : 4057 4047 4024 4133 4100 )

/* Compile directives. */
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, MyDriver_Unload)
#pragma alloc_text(PAGE, MyDriver_UnSupportedFunction)
#pragma alloc_text(PAGE, DispatchCreate)
#pragma alloc_text(PAGE, DispatchClose)
#pragma alloc_text(PAGE, DispatchRead)
#pragma alloc_text(PAGE, DispatchWrite)
#pragma alloc_text(PAGE, DeviceIoEvent)

/* The structure representing the System Service Table. */
typedef struct SystemServiceTable {
	UINT32* ServiceTable;
	UINT32* CounterTable;
	UINT32		ServiceLimit;
	UINT32* ArgumentTable;
} SST;

/* Declaration of KeServiceDescriptorTable, which is exported by ntoskrnl.exe. */
__declspec(dllimport) SST KeServiceDescriptorTable;


/*
 * Required information for hooking function.
 */
typedef NTSTATUS(*FunctionPrototype00)();
typedef NTSTATUS(*FunctionPrototype01)(long _1);
typedef NTSTATUS(*FunctionPrototype02)(long _1,long _2);
typedef NTSTATUS(*FunctionPrototype03)(long _1,long _2,long _3);
typedef NTSTATUS(*FunctionPrototype04)(long _1,long _2,long _3,long _4);
typedef NTSTATUS(*FunctionPrototype05)(long _1,long _2,long _3,long _4,long _5);
typedef NTSTATUS(*FunctionPrototype06)(long _1,long _2,long _3,long _4,long _5,long _6);
typedef NTSTATUS(*FunctionPrototype07)(long _1,long _2,long _3,long _4,long _5,long _6, long _7);
typedef NTSTATUS(*FunctionPrototype08)(long _1,long _2,long _3,long _4,long _5,long _6, long _7, long _8);
typedef NTSTATUS(*FunctionPrototype09)(long _1,long _2,long _3,long _4,long _5,long _6, long _7, long _8, long _9);
typedef NTSTATUS(*FunctionPrototype10)(long _1,long _2,long _3,long _4,long _5,long _6, long _7, long _8, long _9,
	long _10);
typedef NTSTATUS(*FunctionPrototype11)(long _1,long _2,long _3,long _4,long _5,long _6, long _7, long _8, long _9,
	long _10, long _11);
typedef NTSTATUS(*FunctionPrototype12)(long _1,long _2,long _3,long _4,long _5,long _6, long _7, long _8, long _9,
	long _10, long _11, long _12);
typedef NTSTATUS(*FunctionPrototype13)(long _1,long _2,long _3,long _4,long _5,long _6, long _7, long _8, long _9,
	long _10, long _11, long _12, long _13);
typedef NTSTATUS(*FunctionPrototype14)(long _1,long _2,long _3,long _4,long _5,long _6, long _7, long _8, long _9,
	long _10, long _11, long _12, long _13, long _14);
typedef NTSTATUS(*FunctionPrototype15)(long _1,long _2,long _3,long _4,long _5,long _6, long _7, long _8, long _9,
	long _10, long _11, long _12, long _13, long _14, long _15);
typedef NTSTATUS(*FunctionPrototype16)(long _1,long _2,long _3,long _4,long _5,long _6, long _7, long _8, long _9,
	long _10, long _11, long _12, long _13, long _14, long _15, long _16);
typedef NTSTATUS(*FunctionPrototype17)(long _1, long _2, long _3, long _4, long _5, long _6, long _7, long _8, long _9,
	long _10, long _11, long _12, long _13, long _14, long _15, long _16, long _17);

PVOID oldFunction = NULL;
ULONG count = 0;
ULONG hooked_function_index = 157;

/*
 * Disable the WP bit in CR0 register.
 */
void DisableWP() {
	__asm {
		push edx;
		mov edx, cr0;
		and edx, 0xFFFEFFFF;
		mov cr0, edx;
		pop edx;
	}
}

/*
 * Enable the WP bit in CR0 register.
 */
void EnableWP() {
	__asm {
		push edx;
		mov edx, cr0;
		or edx, 0x00010000;
		mov cr0, edx;
		pop edx;
	}
}

/*
 * Hook Function.
 */
NTSTATUS Hook_Function00()
{
	count++;
	return ((FunctionPrototype00)oldFunction)();
}
NTSTATUS Hook_Function01(long _1)
{
	count++;
	return ((FunctionPrototype01)oldFunction)(_1);
}
NTSTATUS Hook_Function02(long _1, long _2)
{
	count++;
	return ((FunctionPrototype02)oldFunction)(_1, _2);
}
NTSTATUS Hook_Function03(long _1, long _2, long _3)
{
	count++;
	return ((FunctionPrototype03)oldFunction)(_1, _2, _3);
}
NTSTATUS Hook_Function04(long _1, long _2, long _3, long _4) 
{
	count++;
	return ((FunctionPrototype04)oldFunction)(_1, _2, _3, _4);
}
NTSTATUS Hook_Function05(long _1, long _2, long _3, long _4, long _5)
{
	count++;
	return ((FunctionPrototype05)oldFunction)(_1, _2, _3, _4, _5);
}
NTSTATUS Hook_Function06(long _1, long _2, long _3, long _4, long _5, long _6)
{
	count++;
	return ((FunctionPrototype06)oldFunction)(_1, _2, _3, _4, _5, _6);
}
NTSTATUS Hook_Function07(long _1, long _2, long _3, long _4, long _5, long _6, long _7)
{
	count++;
	return ((FunctionPrototype07)oldFunction)(_1, _2, _3, _4, _5, _6, _7);
}
NTSTATUS Hook_Function08(long _1, long _2, long _3, long _4, long _5, long _6, long _7, long _8)
{
	count++;
	return ((FunctionPrototype08)oldFunction)(_1, _2, _3, _4, _5, _6, _7, _8);
}
NTSTATUS Hook_Function09(long _1, long _2, long _3, long _4, long _5, long _6, long _7, long _8, long _9)
{
	count++;
	return ((FunctionPrototype09)oldFunction)(_1, _2, _3, _4, _5, _6, _7, _8, _9);
}
NTSTATUS Hook_Function10(long _1, long _2, long _3, long _4, long _5, long _6, long _7, long _8, long _9, long _10)
{
	count++;
	return ((FunctionPrototype10)oldFunction)(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10);
}
NTSTATUS Hook_Function11(long _1, long _2, long _3, long _4, long _5, long _6, long _7, long _8, long _9, long _10, long _11)
{
	count++;
	return ((FunctionPrototype11)oldFunction)(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11);
}
NTSTATUS Hook_Function12(long _1, long _2, long _3, long _4, long _5, long _6, long _7, long _8, long _9, long _10, long _11, long _12)
{
	count++;
	return ((FunctionPrototype12)oldFunction)(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12);
}
NTSTATUS Hook_Function13(long _1, long _2, long _3, long _4, long _5, long _6, long _7, long _8, long _9, long _10, long _11, long _12, long _13)
{
	count++;
	return ((FunctionPrototype13)oldFunction)(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13);
}
NTSTATUS Hook_Function14(long _1, long _2, long _3, long _4, long _5, long _6, long _7, long _8, long _9, long _10, long _11, long _12, long _13, long _14)
{
	count++;
	return ((FunctionPrototype14)oldFunction)(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14);
}
NTSTATUS Hook_Function15(long _1, long _2, long _3, long _4, long _5, long _6, long _7, long _8, long _9, long _10, long _11, long _12, long _13, long _14, long _15)
{
	count++;
	return ((FunctionPrototype15)oldFunction)(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15);
}
NTSTATUS Hook_Function16(long _1, long _2, long _3, long _4, long _5, long _6, long _7, long _8, long _9, long _10, long _11, long _12, long _13, long _14, long _15, long _16)
{
	count++;
	return ((FunctionPrototype16)oldFunction)(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16);
}
NTSTATUS Hook_Function17(long _1, long _2, long _3, long _4, long _5, long _6, long _7, long _8, long _9, long _10, long _11, long _12, long _13, long _14, long _15, long _16, long _17)
{
	count++;
	return ((FunctionPrototype17)oldFunction)(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17);
}

/*
 * A function that hooks the 'syscall' function in SSDT.
 */
PULONG HookSSDT(ULONG basic_state) {

	/* disable WP bit in CR0 to enable writing to SSDT */
	DisableWP();
	DbgPrint("The WP flag in CR0 has been disabled.\r\n");

	/* identify the address of SSDT table */
	PLONG ssdt = KeServiceDescriptorTable.ServiceTable;
	PCHAR argument_t = KeServiceDescriptorTable.ArgumentTable;

	/* get the address of the service routine in SSDT */
	PLONG target = (PLONG) & (ssdt[hooked_function_index]);
	DbgPrint("The address of the SSDT routine to be hooked is: %x.\r\n", target);
	/*DbgPrint("number of bytes of functions: \r\n");
	for (unsigned i = 0; i < KeServiceDescriptorTable.ServiceLimit; i++)
	{
		DbgPrint("%u: %u \r\n", i, argument_t[i]);
	}*/

	/* hook the service routine in SSDT */
	count = 0;
	PULONG returned_value;
	if (basic_state == TRUE)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)oldFunction);
		EnableWP();
		return returned_value;
	}
	
	if (argument_t[hooked_function_index] == 0)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function00);
	}
	else if (argument_t[hooked_function_index] == 4)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function01);
	}
	else if (argument_t[hooked_function_index] == 8)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function02);
	}
	else if (argument_t[hooked_function_index] == 12)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function03);
	}
	else if (argument_t[hooked_function_index] == 16)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function04);
	}
	else if (argument_t[hooked_function_index] == 20)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function05);
	}
	else if (argument_t[hooked_function_index] == 24)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function06);
	}
	else if (argument_t[hooked_function_index] == 28)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function07);
	}
	else if (argument_t[hooked_function_index] == 32)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function08);
	}
	else if (argument_t[hooked_function_index] == 36)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function09);
	}
	else if (argument_t[hooked_function_index] == 40)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function10);
	}
	else if (argument_t[hooked_function_index] == 44)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function11);
	}
	else if (argument_t[hooked_function_index] == 48)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function12);
	}
	else if (argument_t[hooked_function_index] == 52)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function13);
	}
	else if (argument_t[hooked_function_index] == 56)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function14);
	}
	else if (argument_t[hooked_function_index] == 60)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function15);
	}
	else if (argument_t[hooked_function_index] == 64)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function16);
	}
	else if (argument_t[hooked_function_index] == 68)
	{
		returned_value = (PUCHAR)InterlockedExchange(target, (PUCHAR)Hook_Function17);
	}
	else
	{
		DbgPrint("It's not possible to hook \r\n");
		returned_value = NULL;
	}
	EnableWP();
	return returned_value;
}

/*
 * DriverEntry: entry point for drivers.
 */
NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath) {
	NTSTATUS NtStatus = STATUS_SUCCESS;
	//unsigned int uiIndex = 0;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING usDriverName, usDosDeviceName;

	DbgPrint("DriverEntry Called \r\n");

	RtlInitUnicodeString(&usDriverName, L"\\Device\\MyDriver");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\MyDriver");

	NtStatus = IoCreateDevice(pDriverObject, sizeof(REGISTER_EVENT), &usDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);

	if (NtStatus != STATUS_SUCCESS)
	{
		DbgPrint("IoCreateDevice nie dziala \r\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	pDeviceObject->Flags |= DO_BUFFERED_IO;
	pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);

	/* Create a Symbolic Link to the device. MyDriver -> \Device\MyDriver */
	IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);

	if (NtStatus != STATUS_SUCCESS)
	{
		DbgPrint("IoCreateSymbolicLink nie dziala \r\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	/* MajorFunction: is a list of function pointers for entry points into the driver. */
	/*for (uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++)
	{
		pDriverObject->MajorFunction[uiIndex] = MyDriver_UnSupportedFunction;

	}*/
	//Implement basic Driver function pointers
	// This includes Dispatch routines for Create,Close , Read, Write and IO control
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_READ] = DispatchRead;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchWrite;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoEvent;
	/* DriverUnload is required to be able to dynamically unload the driver. */
	pDriverObject->DriverUnload = MyDriver_Unload;

	driverExtension = ExAllocatePoolWithTag(NonPagedPool, sizeof(REGISTER_EVENT), '1gaT');

	if (!driverExtension)
	{
		DbgPrint("ExAllocatePool nie dziala \r\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(driverExtension->EventParameter, BUFFERSIZE);

	/* hook SSDT */
	oldFunction = HookSSDT(FALSE);

	return NtStatus;
}


/*
 * MyDriver_Unload: called when the driver is unloaded.
 */
VOID MyDriver_Unload(PDRIVER_OBJECT  DriverObject) {
	/* local variables */
	UNICODE_STRING usDosDeviceName;

	/* restore the hook */
	if (oldFunction != NULL) {
		oldFunction = HookSSDT(TRUE);
		
		DbgPrint("The original SSDT function restored.\r\n");
	}

	/* delete the driver */
	DbgPrint("MyDriver_Unload Called \r\n");
	ExFreePoolWithTag(driverExtension, '1gaT');
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\MyDriver");
	IoDeleteSymbolicLink(&usDosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);
}


/*
 * MyDriver_UnSupportedFunction: called when a major function is issued that isn't supported.
 */
NTSTATUS MyDriver_UnSupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS NtStatus = STATUS_NOT_SUPPORTED;
	DbgPrint("MyDriver_UnSupportedFunction Called \r\n");

	return NtStatus;
}

//Called when the application creates this device
NTSTATUS DispatchCreate(PDEVICE_OBJECT    pDevObj, PIRP pIrp)
{
	DbgPrint("Inside Dispatch Create Routine \r\n");
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;

}
//Called when the application reads data from this device
NTSTATUS DispatchRead(PDEVICE_OBJECT    pDevObj, PIRP pIrp)
{
	DbgPrint("Inside Dispatch Read Routine \r\n");
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
//Called when the application writes data to this device
NTSTATUS DispatchWrite(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("Inside Dispatch Write Routine \r\n");
	//Read the data form the User Mode Application..
	if (pIrp->AssociatedIrp.SystemBuffer == NULL)
	{
		DbgPrint("pIrp->AssociatedIrp.SystemBuffer pusty \r\n");
	}
	else
	{
		ULONG num_of_entries = KeServiceDescriptorTable.ServiceLimit;
		if (((char*)(pIrp->AssociatedIrp.SystemBuffer))[0] == 's')
		{
			//DbgPrint("num of entries: %u \r\n", num_of_entries);
			//DbgPrint(pIrp->AssociatedIrp.SystemBuffer);
			DbgPrint("how many calls: %u \r\n", count);
		}
		else if (((char*)(pIrp->AssociatedIrp.SystemBuffer))[0] == 'c')
		{
			count = 0;
			DbgPrint("counter to zero \r\n");
		}
		else if (((char*)(pIrp->AssociatedIrp.SystemBuffer))[0] >= '0' && ((char*)(pIrp->AssociatedIrp.SystemBuffer))[0] <= '9')
		{
			char* temp_pointer = (char*)(pIrp->AssociatedIrp.SystemBuffer);
			ULONG num_of_func = (temp_pointer[0] - '0') * 1000 + (temp_pointer[1] - '0') * 100 + (temp_pointer[2] - '0') * 10 + (temp_pointer[3] - '0');
			if (num_of_func < num_of_entries)
			{
				DbgPrint("function to count: %u \r\n", num_of_func);
				if (oldFunction != NULL) {
					oldFunction = HookSSDT(TRUE);
					oldFunction = NULL;
					DbgPrint("The original SSDT function restored.\r\n");
				}
				hooked_function_index = num_of_func;
				oldFunction = HookSSDT(FALSE);
			}
			else
			{
				DbgPrint("wrong number \r\n");
			}
		}
	}
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
//Called when the application closes the device Handle
NTSTATUS DispatchClose(IN PDEVICE_OBJECT    pDevObj, IN PIRP pIrp)
{
	DbgPrint("Inside Create Dispatch Close Routine \r\n");

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
//Called when the application the application invokes IO control Events
NTSTATUS DeviceIoEvent(IN PDEVICE_OBJECT    DeviceObject, IN PIRP pIrp)
{
	DbgPrint("Inside DeviceIoEvent Routine \r\n");
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;

}