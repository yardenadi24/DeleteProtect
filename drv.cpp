#include <ntifs.h>
#include <fltKernel.h> // Need to add to the linker: fltmgr.lib

NTSTATUS InitMiniFilter(PUNICODE_STRING RegistryPath);

FLT_PREOP_CALLBACK_STATUS DelProtectPreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS DelProtectPreSetInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext);

NTSTATUS DelProtectUnload (FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS DelProtectInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

VOID
DelProtectInstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason);

NTSTATUS
DelProtectInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

VOID 
DelProtectInstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason);

extern "C"
NTSTATUS
ZwQueryInformationProcess(HANDLE hProcess, PROCESSINFOCLASS InfoClass, PVOID Buffer, ULONG Size, PULONG Needed);


#define MAX_PATH 256
PFLT_FILTER g_Filter;

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
	
	const FLT_OPERATION_REGISTRATION Callbacks[] = {
		{ IRP_MJ_CREATE, 0, DelProtectPreCreate, NULL },
		{ IRP_MJ_SET_INFORMATION, 0, DelProtectPreSetInformation, NULL },
		{ IRP_MJ_OPERATION_END }
	};

	const FLT_REGISTRATION Reg = {
		sizeof(FLT_REGISTRATION),
		FLT_REGISTRATION_VERSION,
		0, // Flags
		NULL, // Context
		Callbacks, // Operation callbacks
		DelProtectUnload, // MiniFilterUnload
		DelProtectInstanceSetup, // InstanceSetup
		DelProtectInstanceQueryTeardown, // InstanceQueryTeardown
		DelProtectInstanceTeardownStart, // InstanceTeardownStart
		DelProtectInstanceTeardownComplete, // InstanceTeardownComplete
	};


	Status = FltRegisterFilter(DriverObject, &Reg, &g_Filter);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("Failed to FltRegisterFilter 0x%u", Status);
		return Status;
	}

	Status = FltStartFiltering(g_Filter);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("Failed to FltStartFiltering 0x%u", Status);
		FltUnregisterFilter(g_Filter);
		return Status;
	}

	return Status;
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
		Status = ZwOpenKey(&hKey, KEY_WRITE, &keyAttr);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("Failed to ZwOpenKey 0x%u", Status);
			break;
		}

		UNICODE_STRING subKey = RTL_CONSTANT_STRING(L"Instances");
		OBJECT_ATTRIBUTES subKeyAttr;
		InitializeObjectAttributes(&subKeyAttr, &subKey, OBJ_KERNEL_HANDLE, hKey, nullptr);
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
		Status = ZwSetValueKey(hInstKey, &flagsName, 0, REG_DWORD, &flags, sizeof(flags));
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("Failed to ZwSetValueKey 0x%u", Status);
			break;
		}
	} while (false);
	
	if(hKey)
		ZwClose(hKey);
	if (hSubKey)
		ZwClose(hSubKey);
	if (hInstKey)
		ZwClose(hInstKey);

	return Status;
}

NTSTATUS
DelProtectUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);
	FltUnregisterFilter(g_Filter);
	return STATUS_SUCCESS;
}

NTSTATUS DelProtectInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	return STATUS_SUCCESS;
}

VOID
DelProtectInstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Reason);
}

VOID
DelProtectInstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Reason);
}

NTSTATUS
DelProtectInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);

	if (VolumeFilesystemType != FLT_FSTYPE_NTFS)
	{
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS DelProtectPreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	// For delete purpose there are 2 ways to delete a file
	// 1. Open a file with a flag indicating delete on close  (FILE_DELETE_ON_CLOSE)
	//    which we will address here

	if (Data->RequestorMode == KernelMode)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (Data->Iopb->Parameters.Create.Options & FILE_DELETE_ON_CLOSE)
	{
		// Delete attempt
		UCHAR Buffer[MAX_PATH];
		NTSTATUS Status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName, Buffer, sizeof(Buffer), NULL);
		if(NT_SUCCESS(Status))
		{
			PUNICODE_STRING Path = (PUNICODE_STRING)Buffer;
			KdPrint(("Process image: %wZ\n", Path));
			UNICODE_STRING Cmd = RTL_CONSTANT_STRING(L"\\System32\\cmd.exe");
			if (RtlSuffixUnicodeString(&Cmd, Path, TRUE))
			{
				KdPrint(("File '%wZ' NOT deleted \n", FltObjects->FileObject->FileName));
				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				return FLT_PREOP_COMPLETE;
			}
		}
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS DelProtectPreSetInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}