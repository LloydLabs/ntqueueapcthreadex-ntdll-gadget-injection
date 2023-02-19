#pragma once

#include <Windows.h>

// https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html

typedef 
VOID
(*PPS_APC_ROUTINE)(
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
);


typedef
NTSTATUS
(*_NtQueueApcThreadEx)(
	_In_ HANDLE ThreadHandle,
	_In_opt_ HANDLE UserApcReserveHandle,
	_In_ PPS_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
);

typedef
NTSTATUS
(*_NtTestAlert)(
	VOID
);