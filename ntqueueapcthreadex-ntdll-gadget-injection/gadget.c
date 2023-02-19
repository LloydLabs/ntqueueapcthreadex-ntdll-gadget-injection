#include "gadget.h"

static
BOOL
gadget_match_valid(
    PBYTE pbAddress
)
{
    return (*pbAddress != 0x5C && (*pbAddress & (~0xF)) == 0x50) && *(pbAddress + 1) == 0xC3;
}

LPVOID
gadget_find_rand_pop_ret(
    HANDLE hProcess,
    LPCWSTR lpcszModule
)
{
    HMODULE hNtDLL = GetModuleHandle(lpcszModule);
    if (hNtDLL == NULL)
    {
        return NULL;
    }

    MODULEINFO ntMi;
    if (!GetModuleInformation(hProcess, hNtDLL, &ntMi, sizeof(ntMi)))
    {
        return NULL;
    }

    PIMAGE_DOS_HEADER pDOSHdr = (PIMAGE_DOS_HEADER)ntMi.lpBaseOfDll;
    if (pDOSHdr->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    PIMAGE_NT_HEADERS pNTHdr = (PIMAGE_NT_HEADERS)((LPBYTE)ntMi.lpBaseOfDll + pDOSHdr->e_lfanew);
    if (pNTHdr->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    LPVOID lpaGadgets[MAX_GADGETS];
    RtlSecureZeroMemory(lpaGadgets, sizeof(lpaGadgets));

    DWORD dwGadgetCount = 0;
    for (WORD i = 0; i < pNTHdr->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER pSectHdr = (PIMAGE_SECTION_HEADER)((PBYTE)IMAGE_FIRST_SECTION(pNTHdr) + (IMAGE_SIZEOF_SECTION_HEADER * i));

        if (
            (pSectHdr->Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE &&
            (pSectHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE
            )
        {
            LPBYTE lpbSectionBase = (LPBYTE)ntMi.lpBaseOfDll + pSectHdr->VirtualAddress;
            LPBYTE lpbSectionEnd = (LPBYTE)lpbSectionBase + pSectHdr->Misc.VirtualSize;

            for (PBYTE lpbCurAddr = lpbSectionBase; lpbCurAddr < lpbSectionEnd; lpbCurAddr++)
            {
                if (!gadget_match_valid(lpbCurAddr))
                {
                    continue;
                }

                lpaGadgets[dwGadgetCount++] = lpbCurAddr;

                if (dwGadgetCount == MAX_GADGETS)
                {
                    break;
                }
            }
        }
    }

    return lpaGadgets[RANDOM_NUMB(0, dwGadgetCount)];
}