/*++

Copyright (c) 2023 Luc Bonnafoux

Module Name:

	keysasCommunication.c

Abstract:

	Contains the function to connect and disconnect communication port with the user.

Environment:

	Kernel mode

--*/

#include "keysasCommunication.h"

#include <fltKernel.h>
#include <ntddstor.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
#include <ntdef.h>
#include <wdm.h>

#include "KeysasMinifilter.h"
#include "keysasFile.h"
#include "keysasInstance.h"
#include "keysasUtils.h"

// Name of the port used to communicate with user space
const PWSTR KeysasPortName = L"\\KeysasPort";

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, KeysasPortConnect)
#pragma alloc_text(PAGE, KeysasPortDisconnect)
#pragma alloc_text(PAGE, KeysasPortNotify)
#endif

NTSTATUS
KeysasInitPort(

)
/*++
Routine Description
	Initialize the communication ports
Arguments
Return Value
	STATUS_SUCCESS - if the initialization is successful
--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING uniPortName = { 0 };
	PSECURITY_DESCRIPTOR sd = NULL;
	OBJECT_ATTRIBUTES oa = { 0 };

	RtlInitUnicodeString(&uniPortName, KeysasPortName);
	// Secure the port so only ADMINs & SYSTEM can access it
	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

	if (NT_SUCCESS(status)) {
		InitializeObjectAttributes(
			&oa,
			&uniPortName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			sd
		);

		status = FltCreateCommunicationPort(
			KeysasData.Filter,
			&KeysasData.ServerPort,
			&oa,
			NULL,
			KeysasPortConnect,
			KeysasPortDisconnect,
			KeysasPortNotify,
			1
		);

		FltFreeSecurityDescriptor(sd);
	}
	else {
		status = STATUS_UNSUCCESSFUL;
	}

	return status;
}

NTSTATUS
KeysasPortConnect(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID* ConnectionCookie
)
/*++
Routine Description
	This is called when user-mode connects to the server port - to establish a
	connection
Arguments
	ClientPort - This is the client connection port that will be used to
		send messages from the filter
	ServerPortCookie - The context associated with this port when the
		minifilter created this port.
	ConnectionContext - Context from entity connecting to this port (most likely
		your user mode service)
	SizeofContext - Size of ConnectionContext in bytes
	ConnectionCookie - Context to be passed to the port disconnect routine.
Return Value
	STATUS_SUCCESS - to accept the connection
--*/
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

	FLT_ASSERT(KeysasData.ClientPort == NULL);
	FLT_ASSERT(KeysasData.UserProcess == NULL);

	// Set the user process and port
	KeysasData.UserProcess = PsGetCurrentProcess();
	KeysasData.ClientPort = ClientPort;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!keysasPortConnect: Connected user, process=0x%p, port=0x%p\n",
		KeysasData.UserProcess,
		KeysasData.ClientPort));

	return STATUS_SUCCESS;
}

VOID
KeysasPortDisconnect(
	_In_opt_ PVOID ConnectionCookie
)
/*++
Routine Description
	This is called when the connection is torn-down. We use it to close our
	handle to the connection
Arguments
	ConnectionCookie - Context from the port connect routine
Return value
	None
--*/
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ConnectionCookie);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!keysasPortDisconnect: Connected user, port=0x%p\n", KeysasData.ClientPort));

	FltCloseClientPort(KeysasData.Filter, &KeysasData.ClientPort);

	KeysasData.UserProcess = NULL;
}

NTSTATUS
KeysasPortNotify (
	_In_ PVOID ConnectionCookie,
	_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
	_In_ ULONG InputBufferSize,
	_Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	_In_ ULONG OutputBufferSize,
	_Out_ PULONG ReturnOutputBufferLength
)
/*++
Routine Description
	This is called when a request is received from userspace.
	Two message types are supported:
	  KEYSAS_MSG_FILE_AUTH (0x01): update file authorization
	    Layout: [0x01 | file_id_32 | auth_u8]  = 34 bytes
	  KEYSAS_MSG_USB_AUTH (0x02): update USB volume authorization
	    Layout: [0x02 | auth_u8 | nt_vol_name_utf16_null]  >= 4 bytes
Arguments
	ConnectionCookie - Not used (single client)
	InputBuffer      - Message from the daemon
	InputBufferSize  - Size of InputBuffer in bytes
	OutputBuffer     - Not used
	OutputBufferSize - Not used
	ReturnOutputBufferLength - Set to 0 (no reply data)
Return value
	STATUS_SUCCESS on success, error status otherwise
--*/
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ConnectionCookie);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferSize);

	PUCHAR inputBuffer = (PUCHAR)InputBuffer;

	*ReturnOutputBufferLength = 0;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasPortNotify: Entered\n"));

	if (NULL == InputBuffer || InputBufferSize < 2) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasPortNotify: Buffer too small\n"));
		return STATUS_UNSUCCESSFUL;
	}

	UINT8 msgType = inputBuffer[0];

	// ── File authorization update ─────────────────────────────────────────────
	if (msgType == KEYSAS_MSG_FILE_AUTH) {

		// Expected layout: [0x01 | file_id_32 | auth_u8]
		if (InputBufferSize < 34) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasPortNotify: FILE_AUTH message too short\n"));
			return STATUS_UNSUCCESSFUL;
		}

		if (TRUE == IsListEmpty(&KeysasData.FileCtxListHead)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasPortNotify: File context list is empty\n"));
			return STATUS_SUCCESS;
		}

		KIRQL kIrql = KeGetCurrentIrql();
		KeAcquireSpinLock(&KeysasData.FileCtxListLock, &kIrql);

		PLIST_ENTRY scan, next;
		PKEYSAS_FILE_CTX fileCtx = NULL;

		for (scan = KeysasData.FileCtxListHead.Flink, next = scan->Flink;
			 scan != &KeysasData.FileCtxListHead;
			 scan = next, next = scan->Flink) {

			fileCtx = CONTAINING_RECORD(scan, KEYSAS_FILE_CTX, FileCtxList);
			if (32 == RtlCompareMemory(fileCtx->FileID, &inputBuffer[1], 32)) {
				fileCtx->Authorization = (KEYSAS_AUTHORIZATION)inputBuffer[33];
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
					"Keysas!KeysasPortNotify: FILE_AUTH updated to %d\n", inputBuffer[33]));
				break;
			}
		}

		KeReleaseSpinLock(&KeysasData.FileCtxListLock, kIrql);

	// ── USB volume authorization update ──────────────────────────────────────
	} else if (msgType == KEYSAS_MSG_USB_AUTH) {

		// Expected layout: [0x02 | auth_u8 | nt_vol_name_utf16_null]
		// Minimum: type(1) + auth(1) + one UTF-16 null char(2) = 4 bytes
		if (InputBufferSize < 4) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasPortNotify: USB_AUTH message too short\n"));
			return STATUS_UNSUCCESSFUL;
		}

		// The volume name payload must be UTF-16 aligned and null-terminated within bounds.
		ULONG payloadBytes = InputBufferSize - 2;
		if ((payloadBytes % sizeof(WCHAR)) != 0) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasPortNotify: USB_AUTH payload not WCHAR-aligned\n"));
			return STATUS_UNSUCCESSFUL;
		}

		PCWSTR volNamePtr = (PCWSTR)(&inputBuffer[2]);
		ULONG maxWchars = payloadBytes / sizeof(WCHAR);
		ULONG volNameLen = 0;
		while (volNameLen < maxWchars && volNamePtr[volNameLen] != L'\0') {
			volNameLen++;
		}
		if (volNameLen >= maxWchars) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasPortNotify: USB_AUTH volume name not null-terminated\n"));
			return STATUS_UNSUCCESSFUL;
		}
		// Reject excessively long volume names (NT device paths are at most ~256 chars).
		if (volNameLen > 256) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasPortNotify: USB_AUTH volume name too long\n"));
			return STATUS_UNSUCCESSFUL;
		}

		KEYSAS_AUTHORIZATION auth = (KEYSAS_AUTHORIZATION)inputBuffer[1];
		UNICODE_STRING targetVolName;
		targetVolName.Length = (USHORT)(volNameLen * sizeof(WCHAR));
		targetVolName.MaximumLength = targetVolName.Length + (USHORT)sizeof(WCHAR);
		targetVolName.Buffer = (PWCH)volNamePtr;

		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"Keysas!KeysasPortNotify: USB_AUTH for volume %wZ auth=%d\n", &targetVolName, auth));

		// Enumerate all filter instances to find the one matching this volume
		ULONG instanceCount = 0;
		NTSTATUS status = FltEnumerateInstances(NULL, KeysasData.Filter, NULL, 0, &instanceCount);

		if (instanceCount == 0) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasPortNotify: No instances attached\n"));
			return STATUS_SUCCESS;
		}

		PFLT_INSTANCE* instances = (PFLT_INSTANCE*)ExAllocatePool2(
			POOL_FLAG_NON_PAGED,
			instanceCount * sizeof(PFLT_INSTANCE),
			KEYSAS_MEMORY_TAG
		);
		if (NULL == instances) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		status = FltEnumerateInstances(NULL, KeysasData.Filter, instances, instanceCount, &instanceCount);
		if (!NT_SUCCESS(status)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
				"Keysas!KeysasPortNotify: FltEnumerateInstances failed 0x%08x\n", status));
			ExFreePoolWithTag(instances, KEYSAS_MEMORY_TAG);
			return STATUS_SUCCESS;
		}

		for (ULONG i = 0; i < instanceCount; i++) {
			PFLT_VOLUME volume = NULL;

			if (!NT_SUCCESS(FltGetVolumeFromInstance(instances[i], &volume))) {
				FltObjectDereference(instances[i]);
				continue;
			}

			wchar_t volNameBuf[512] = { 0 };
			UNICODE_STRING volName = { 0, sizeof(volNameBuf) - sizeof(wchar_t), volNameBuf };

			if (NT_SUCCESS(FltGetVolumeName(volume, &volName, NULL))) {
				if (RtlEqualUnicodeString(&volName, &targetVolName, TRUE)) {
					// Found the matching instance — update its context
					PKEYSAS_INSTANCE_CTX instanceCtx = NULL;
					if (NT_SUCCESS(FltGetInstanceContext(instances[i], (PFLT_CONTEXT*)&instanceCtx))) {
						AcquireResourceWrite(instanceCtx->Resource);
						instanceCtx->Authorization = auth;
						ReleaseResource(instanceCtx->Resource);
						FltReleaseContext(instanceCtx);
						KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
							"Keysas!KeysasPortNotify: USB_AUTH applied to volume %wZ\n", &volName));
					}
				}
			}

			FltObjectDereference(volume);
			FltObjectDereference(instances[i]);
		}

		ExFreePoolWithTag(instances, KEYSAS_MEMORY_TAG);

	} else {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"Keysas!KeysasPortNotify: Unknown message type 0x%02x\n", msgType));
		return STATUS_UNSUCCESSFUL;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasPortNotify: Done\n"));
	return STATUS_SUCCESS;
}