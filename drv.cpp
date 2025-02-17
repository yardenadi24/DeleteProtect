#include <ntifs.h>
#include <fltKernel.h> // Need to add to the linker: fltmgr.lib

#pragma warning(disable: 4996)

#define DRIVER_TAG 'ledp'

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
	(FlagOn(gTraceFlags,(_dbgLevel)) ?              \
		DbgPrint _string :                          \
		((int)0))


// Prototypes

//// Instance
NTSTATUS
DelProtectInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS
DelProtectUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

VOID
DelProtectInstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
DelProtectInstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
DelProtectInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

// Prototypes


// Callbacks

FLT_PREOP_CALLBACK_STATUS DelProtectPreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	PVOID*);

FLT_PREOP_CALLBACK_STATUS DelProtectPreSetInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext);



// Callbacks

NTSTATUS InitMiniFilter(PUNICODE_STRING RegistryPath);

extern "C" NTSTATUS ZwQueryInformationProcess(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);

BOOLEAN IsDeleteAllowed(const PEPROCESS Process);

#define MAX_PATH 256
PFLT_FILTER gFilterHandle;

extern "C"
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
)
{
	NTSTATUS Status = InitMiniFilter(RegistryPath);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("Failed to InitMiniFilter 0x%u", Status);
		return Status;
	}
	
	CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
		{ IRP_MJ_CREATE, 0, DelProtectPreCreate, nullptr },
		{ IRP_MJ_SET_INFORMATION, 0, DelProtectPreSetInformation, nullptr },
		{ IRP_MJ_OPERATION_END }
	};

	CONST FLT_REGISTRATION FilterRegistration = {

		sizeof(FLT_REGISTRATION),
		FLT_REGISTRATION_VERSION,
		0,                       //  Flags

		nullptr,                 //  Context
		Callbacks,               //  Operation callbacks

		DelProtectUnload,                   //  MiniFilterUnload

		DelProtectInstanceSetup,            //  InstanceSetup
		DelProtectInstanceQueryTeardown,    //  InstanceQueryTeardown
		DelProtectInstanceTeardownStart,    //  InstanceTeardownStart
		DelProtectInstanceTeardownComplete, //  InstanceTeardownComplete
	};


	Status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("Failed to FltRegisterFilter 0x%u", Status);
		return Status;
	}

	Status = FltStartFiltering(gFilterHandle);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("Failed to FltStartFiltering 0x%u", Status);
		FltUnregisterFilter(gFilterHandle);
		return Status;
	}

	return Status;
}

NTSTATUS
DelProtectInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("DelProtect!DelProtectInstanceSetup: Entered\n"));

	return STATUS_SUCCESS;
}

NTSTATUS
DelProtectInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("DelProtect!DelProtectInstanceQueryTeardown: Entered\n"));

	return STATUS_SUCCESS;
}

VOID
DelProtectInstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("DelProtect!DelProtectInstanceTeardownStart: Entered\n"));
}

VOID
DelProtectInstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("DelProtect!DelProtectInstanceTeardownComplete: Entered\n"));
}

NTSTATUS
DelProtectUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("DelProtect!DelProtectUnload: Entered\n"));

	FltUnregisterFilter(gFilterHandle);

	return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
DelProtectPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("DelProtect!DelProtectPreOperation: Entered\n"));

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


VOID
DelProtectOperationStatusCallback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
	_In_ NTSTATUS OperationStatus,
	_In_ PVOID RequesterContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("DelProtect!DelProtectOperationStatusCallback: Entered\n"));

	PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
		("DelProtect!DelProtectOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
			OperationStatus,
			RequesterContext,
			ParameterSnapshot->MajorFunction,
			ParameterSnapshot->MinorFunction,
			FltGetIrpName(ParameterSnapshot->MajorFunction)));
}

FLT_POSTOP_CALLBACK_STATUS
DelProtectPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("DelProtect!DelProtectPostOperation: Entered\n"));

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
DelProtectPreOperationNoPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("DelProtect!DelProtectPreOperationNoPostOperation: Entered\n"));

	// This template code does not do anything with the callbackData, but
	// rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
	// This passes the request down to the next miniFilter in the chain.

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
DelProtectPreCreate(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID*)
{
	UNREFERENCED_PARAMETER(FltObjects);

	if (Data->RequestorMode == KernelMode)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	auto& params = Data->Iopb->Parameters.Create;
	auto returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (params.Options & FILE_DELETE_ON_CLOSE) {
		// delete operation
		KdPrint(("Delete on close: %wZ\n", &Data->Iopb->TargetFileObject->FileName));

		if (!IsDeleteAllowed(PsGetCurrentProcess())) {
			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			returnStatus = FLT_PREOP_COMPLETE;
			KdPrint(("Prevent delete from IRP_MJ_CREATE by cmd.exe\n"));
		}
	}
	return returnStatus;
}

FLT_PREOP_CALLBACK_STATUS DelProtectPreSetInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Data);

	auto& params = Data->Iopb->Parameters.SetFileInformation;

	if (params.FileInformationClass != FileDispositionInformation && params.FileInformationClass != FileDispositionInformationEx) {
		// not a delete operation
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	auto info = (FILE_DISPOSITION_INFORMATION*)params.InfoBuffer;
	if (!info->DeleteFile)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	auto returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

	// what process did this originate from?
	auto process = PsGetThreadProcess(Data->Thread);
	NT_ASSERT(process);

	if (!IsDeleteAllowed(process)) {
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		returnStatus = FLT_PREOP_COMPLETE;
		KdPrint(("Prevent delete from IRP_MJ_SET_INFORMATION by cmd.exe\n"));
	}

	return returnStatus;
}

BOOLEAN
IsDeleteAllowed(const PEPROCESS Process) {
	bool currentProcess = PsGetCurrentProcess() == Process;
	HANDLE hProcess;
	if (currentProcess)
		hProcess = NtCurrentProcess();
	else {
		auto status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE,
			nullptr, 0, nullptr, KernelMode, &hProcess);
		if (!NT_SUCCESS(status))
			return true;
	}

	auto size = 300;
	bool allowDelete = true;
	auto processName = (UNICODE_STRING*)ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG);

	if (processName) {
		RtlZeroMemory(processName, size);	// ensure string will be NULL-terminated
		auto status = ZwQueryInformationProcess(hProcess, ProcessImageFileName,
			processName, size - sizeof(WCHAR), nullptr);

		if (NT_SUCCESS(status)) {
			KdPrint(("Delete operation from %wZ\n", processName));

			if (processName->Length > 0 && wcsstr(processName->Buffer, L"\\System32\\cmd.exe") != nullptr ||
				wcsstr(processName->Buffer, L"\\SysWOW64\\cmd.exe") != nullptr) {
				allowDelete = false;
			}
		}
		ExFreePool(processName);
	}
	if (!currentProcess)
		ZwClose(hProcess);

	return allowDelete;
}

NTSTATUS
InitMiniFilter(PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE hKey = NULL;
	HANDLE hSubKey = NULL;
	HANDLE hInstKey = NULL;
	do {
		OBJECT_ATTRIBUTES keyAttr = RTL_CONSTANT_OBJECT_ATTRIBUTES(RegistryPath, OBJ_KERNEL_HANDLE);
		KdPrint(("ZwOpenKey(&hKey, KEY_WRITE, &keyAttr)"));
		Status = ZwOpenKey(&hKey, KEY_WRITE, &keyAttr);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("Failed to ZwOpenKey 0x%u", Status);
			break;
		}

		UNICODE_STRING subKey = RTL_CONSTANT_STRING(L"Instances");
		OBJECT_ATTRIBUTES subKeyAttr;
		InitializeObjectAttributes(&subKeyAttr, &subKey, OBJ_KERNEL_HANDLE, hKey, nullptr);
		KdPrint(("ZwCreateKey(&hSubKey, KEY_WRITE, &subKeyAttr, 0, nullptr, 0, nullptr);"));
		Status = ZwCreateKey(&hSubKey, KEY_WRITE, &subKeyAttr, 0, nullptr, 0, nullptr);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("Failed to ZwCreateKey 0x%u", Status);
			break;
		}
		//
		// set "DefaultInstance" value
		//
		UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"DefaultInstance");
		WCHAR name[] = L"DelProtectDefaultInstance"; // Just has to exists
		KdPrint(("ZwSetValueKey(hSubKey, &valueName, 0, REG_SZ, name, sizeof(name));"));
		Status = ZwSetValueKey(hSubKey, &valueName, 0, REG_SZ, name, sizeof(name));
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("Failed to ZwSetValueKey 0x%u", Status);
			break;
		}

		//
		// create "instance" key under "Instances"
		//
		UNICODE_STRING instKeyName;
		RtlInitUnicodeString(&instKeyName, name);
		InitializeObjectAttributes(&subKeyAttr, &instKeyName, OBJ_KERNEL_HANDLE, hSubKey, nullptr);
		KdPrint(("ZwCreateKey(&hInstKey, KEY_WRITE, &subKeyAttr, 0, nullptr, 0, nullptr);"));
		Status = ZwCreateKey(&hInstKey, KEY_WRITE, &subKeyAttr, 0, nullptr, 0, nullptr);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("Failed to ZwCreateKey 0x%u", Status);
			break;
		}

		//
		// write out altitude
		//
		WCHAR altitude[] = L"35348.1234567";
		UNICODE_STRING altitudeName = RTL_CONSTANT_STRING(L"Altitude");
		KdPrint(("ZwSetValueKey(hInstKey, &altitudeName, 0, REG_SZ, altitude, sizeof(altitude));"));
		Status = ZwSetValueKey(hInstKey, &altitudeName, 0, REG_SZ, altitude, sizeof(altitude));
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("Failed to ZwSetValueKey 0x%u", Status);
			break;
		}
		
		//
		// write out flags
		//
		UNICODE_STRING flagsName = RTL_CONSTANT_STRING(L"Flags");
		ULONG flags = 0;
		KdPrint(("ZwSetValueKey(hInstKey, &flagsName, 0, REG_DWORD, &flags, sizeof(flags));"));
		Status = ZwSetValueKey(hInstKey, &flagsName, 0, REG_DWORD, &flags, sizeof(flags));
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("Failed to ZwSetValueKey 0x%u", Status);
			break;
		}
	} while (false);
	
	if (hKey)
	{
		KdPrint(("ZwClose(hKey);;"));
		ZwClose(hKey);
	}
	if (hSubKey)
	{
		KdPrint(("ZwClose(hSubKey);;"));
		ZwClose(hSubKey);
	}
	if (hInstKey)
	{
		KdPrint(("ZwClose(hInstKey);"));
		ZwClose(hInstKey);
	}

	return Status;
}