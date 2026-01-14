# HookPE PoC

**HookPE** is a Proof of Concept (PoC) demonstrating a stealthy code loading technique (Process Doppelgänging / Phantom File variations) using Transactional NTFS (TxF) and kernel function hooking.

## Description

The project demonstrates the ability to inject executable code (payload) into process memory without persisting it on disk in a way visible to users or antivirus software.

Key Features:
*   **Hidden Section**: Payload is written to a temporary file within an NTFS transaction. A memory section is created from it, and then the transaction is rolled back. The file disappears from the disk, but the section remains valid in RAM.
*   **API Hooking**: Uses the **Radiance** library to splice the `NtOpenSection` kernel function.
*   **Load Substitution**: When attempting to load a legitimate decoy DLL (`nevermore.dll`), the hook intercepts the call and substitutes it with the hidden payload section.
*   **Native Loader Benefits**: Unlike Manual Mapping, this technique leverages the native Windows Loader. This means the OS automatically handles complex tasks like CRT initialization, TLS callbacks, and dependency resolution, ensuring unrestricted stability and functionality of the injected payload.

## Technical Details

1.  **TxF (Transactional NTFS)**: A transaction is created (`CreateTransaction`), and a file is created inside it. After creating the section (`NtCreateSection` with `SEC_IMAGE` flag), the transaction is rolled back (`RollbackTransaction`).
2.  **Radiance Hooking Engine**: A modern C++20 library for function splicing. Features:
    *   Instruction length analysis (HDE64).
    *   Trampoline generation.
    *   Correct handling of RIP-relative addressing (including emulation of absolute addressing for far jumps).
3.  **Process Injection**: Standard `LoadLibrary` is used as a trigger. The kernel calls `NtOpenSection`, which is intercepted, mapping our hidden section instead of the disk file.
4.  Tested only on Windows 10 (22h2).

## Build Requirements

*   C++20 compatible compiler (if you want to use radiance lib)
*   CMake 4.0+
*   Ninja Build System (recommended)

## Build

```bash
mkdir build
cd build
cmake -G Ninja ..
cmake --build .
```

## Project Structure

*   `main.cpp` — Main logic: phantom section creation, hook installation, injection trigger.
*   `external/radiance` — Hooking library (submodule).
*   `payload.h` — Byte array containing shellcode/DLL to inject.

## Disclaimer

This code is provided solely for educational purposes to demonstrate Windows internal mechanisms and Red Teaming techniques. The author is not responsible for any illegal use of this code.
