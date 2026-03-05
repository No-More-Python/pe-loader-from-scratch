# 🎓 Learning Windows Internals: Manual PE Mapping
---

## 📖 Introduction
This project is an **educational exploration** into the mechanics of the Windows Portable Executable (PE) loader. While a "Pure" Manual Map would involve mapping every dependent DLL manually, this implementation takes a **Hybrid Approach**: 
* We manually map the **Primary Executable** (Mapping sections, Relocations, and TLS).
* We utilize the Windows API (`LoadLibraryA`) to resolve **External Dependencies** (DLLs).

This provides a balanced look at how the OS handles execution handoff while keeping the educational focus on the structure of the main PE file.

---

## 🔍 The "Hybrid" Import Resolution
In the `resolve_imports` function, we demonstrate how the IAT is structured. Even though we use `LoadLibraryA` to get the base address of dependencies:
1. We must manually navigate the `IMAGE_IMPORT_DESCRIPTOR` array.
2. We must handle the **Thunk data** correctly based on the CPU architecture (4-byte vs 8-byte).
3. We manually patch the function addresses into the allocated memory.


## 🧠 Key Learning Objectives
---
* **PE Header Anatomy**: Understanding the relationship between `IMAGE_DOS_HEADER`, `IMAGE_FILE_HEADER`, and the Optional Headers (`PE32` vs `PE32+`).
* **Memory Relocation**: Implementing base relocation logic to ensure code runs correctly when loaded at a non-preferred memory address.
* **Dynamic Linking**: Deep dive into the **Import Address Table (IAT)** and how DLL dependencies are resolved and patched.
* **TLS Execution**: Learning the role of **Thread Local Storage (TLS)** callbacks and their execution flow before the main entry point.



## 🛠️ The Implementation Pipeline
---
The loader simulates the Windows OS loader through a strict, step-by-step process:

1.  **Header Parsing**: Validates the PE signature and identifies the machine architecture.
2.  **Memory Allocation**: Reserves contiguous memory based on `SizeOfImage` using `VirtualAlloc`.
3.  **Section Mapping**: Copies raw data from file sections into their respective virtual addresses.
4.  **Base Relocation**: Corrects hardcoded addresses if the image is not at its preferred base.
5.  **Import Resolution**: Iterates through the Import Directory, loads DLLs, and populates the IAT with function addresses.
6.  **Security Protection**: Updates memory page permissions (e.g., making `.text` executable) via `VirtualProtect`.
7.  **Execution**: Runs TLS Callbacks followed by a jump to the **Original Entry Point (OEP)**.



## ⚠️ The Architecture Challenge: x86 vs x64
---
A significant portion of this study focused on handling **Architectural Mismatch**. 

### 🔍 The "Pointer Crisis" Bug
During development, a critical bug was identified when resolving imports for 32-bit files within a 64-bit loader:
* **The Problem**: Writing 64-bit pointers (8 bytes) into 32-bit IAT slots (4 bytes) caused memory corruption, overwriting adjacent function entries.
* **The Symptom**: This corruption destroyed the NULL terminator in tables, leading to infinite loops during TLS traversal.

### 🛠️ The Solution
The final implementation uses architecture-aware pointer arithmetic:
* **x64 Mode**: Uses `uint64_t` for IAT patching and 8-byte increments for table traversal.
* **x86 Mode**: Uses `uint32_t` for IAT patching and 4-byte increments.

> **Educational Note:** While this loader can parse and map 32-bit files,
> it is designed to only *execute* compatible 64-bit code
> when running on a 64-bit host to prevent instruction set exceptions (Architecture Guard).

[Image comparing x86 and x64 instruction sets and pointer sizes]

## 🚀 Usage (For Educational Testing)
---
### 1. Compile the Loader
Use GCC to compile the source code into an executable loader
```gcc PeLoader.c -o PeLoader.exe```

### 2. Prepare a Target Binary
Since the TestFile/ directory is included in .gitignore to keep the repository clean, you must provide your own target binary for testing:

Create a simple "Hello World" program in C.
Compile it as a 64-bit executable (e.g., hello64.exe).
Place it inside a folder (e.g., TestFile/).

### 3. Run the Loader
Execute the loader by passing the path of your target binary as an argument:

```./PeLoader.exe TestFile/hello64.exe```
Note: In this context, hello64.exe is a practical example of how to use this PE-loader-from-scratch 
to map and execute a binary without relying on the default OS loading mechanism.

---
## 📂 Project Structure
* `PE_OPTIONAL_COMMON`: Unified structure for handling shared header data.
* `relocation32` / `relocation64`: Architecture-specific relocation logic.
* `resolve_imports`: Smart importer that handles pointer size mismatch.
* `runTLScallsbacks`: Safe callback execution with proper table stepping.

---
**Disclaimer**: This project is for educational purposes only. 
It is intended for students and researchers to learn about Windows internals and low-level system programming.
