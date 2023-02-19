#pragma once

#include <Windows.h>
#include <psapi.h>

#define MAX_GADGETS 512
#define RANDOM_NUMB(min, max) (rand() % (max + 1 - min) + min)

LPVOID
gadget_find_rand_pop_ret(
    HANDLE hProcess,
    LPCWSTR lpcszModule
);