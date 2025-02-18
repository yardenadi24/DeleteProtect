#pragma once
#include <ntifs.h>
#include <fltKernel.h> // Need to add to the linker: fltmgr.lib

#pragma warning(disable: 4996)

#define DRIVER_TAG 'ledp'
#define DRIVER_PREFIX "DelProtect: "

#define LOG(v, ...) DbgPrint(DRIVER_PREFIX "%s::" v "\n",__FUNCTION__, __VA_ARGS__)

// ------------------ Prototypes ------------------ //


// Called when new instance is created
NTSTATUS
DelProtectInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

// Called when unloading the filter
NTSTATUS
DelProtectUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

// Called on instance teardown
VOID
DelProtectInstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

// Called on instance teardown completion
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

// ------------------ Prototypes ------------------ //




// ------------------ Callbacks ------------------ //
FLT_PREOP_CALLBACK_STATUS DelProtectPreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	PVOID*);

FLT_PREOP_CALLBACK_STATUS DelProtectPreSetInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
// ------------------ Callbacks ------------------ //


extern "C" NTSTATUS ZwQueryInformationProcess(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);


BOOLEAN IsDeleteAllowed(const PEPROCESS Process);
NTSTATUS InitMiniFilter(PUNICODE_STRING RegistryPath);

PFLT_FILTER g_FilterHandle;