#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <inttypes.h>

typedef struct {
    uint64_t ImageBase;
    uint32_t AddressOfEntryPoint;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t NumberOfRvaAndSizes;
    uint32_t SectionAlignment;
    uint32_t ImportRVA;
    uint32_t ImportSize;
    uint32_t RelocRVA;
    uint32_t RelocSize;
    uint32_t TlsRVA;
    uint32_t TlsSize;
} PE_OPTIONAL_COMMON;

int rva_to_offset(uint32_t rva, IMAGE_SECTION_HEADER *section, uint16_t numSections,uint32_t *outOffset);
void relocation64(
    uint8_t *imageBase, 
    uint64_t preferredBase, 
    uint32_t relocRVA, 
    uint32_t relocSize
);

void relocation32(
    uint8_t *imageBase, 
    uint32_t preferredBase, 
    uint32_t relocRVA, 
    uint32_t relocSize
);

int resolve_imports(
    uint8_t *imageBase,
    uint32_t importRVA,
    int is64
);

void section_Protections(
    uint8_t *imageBase,
    IMAGE_SECTION_HEADER *sections,
    uint16_t numSections
);

void runTLScallsbacks(
    uint8_t *imageBase,
    uint32_t tlsRVA,
    PE_OPTIONAL_COMMON common,
    int is64
);
void* VaToPtr(uint64_t va, uint64_t imageBase, uint8_t* mappedBase, uint32_t sizeOfImage);
int main(int argc,char **argv){
    if(argc != 2){
        printf("Usage : %s <Filename>\n", argv[0]);
        return 1;
    }
    FILE *f = NULL;
    IMAGE_SECTION_HEADER *sections = NULL;
    uint8_t *headers = NULL;
    uint8_t *buffer = NULL;
    LPVOID imageMemory = NULL;
    int status = 1;

    f = fopen(argv[1], "rb");
    if (!f) return 1;

    IMAGE_DOS_HEADER dos;

    if(fread(&dos, sizeof(dos), 1, f) != 1){
        if(feof(f)){
            printf("File too small to be a PE file\n");
        }else{
            printf("Read error\n");
        }
        goto cleanup; 
    }
    
    if(dos.e_magic != 0x5A4D){
        printf("%s is not PE\n", argv[1]);
        status = 1;
        goto cleanup; 
    }
    fseek(f, 0, SEEK_END);
    long long fileSize = ftell(f);
    rewind(f);
    if((unsigned long)dos.e_lfanew > fileSize - (4 + sizeof(IMAGE_FILE_HEADER))){
        printf("[!] File is too small to contain a valid PE header\n");
        goto cleanup;
    }

    if(fseek(f, dos.e_lfanew, SEEK_SET) != 0){
        printf("Seek failed");
        goto cleanup; 
    }
    uint32_t pe_sig;
    if(fread(&pe_sig, sizeof(pe_sig), 1, f) != 1){
        printf("Read PE signature failed\n");
        goto cleanup; 
    }

    if(pe_sig == 0x00004550){
        printf("%s Valid PE\n", argv[1]);
    }else{
        printf("%s Invalid PE\n", argv[1]);
        goto cleanup;
    }
    
    IMAGE_FILE_HEADER fileHeader;
    if (fread(&fileHeader, sizeof(fileHeader), 1, f) != 1) {
        printf("Read FILE_HEADER failed\n");
        goto cleanup;
    }

    long long cur = ftell(f);
    if(cur < 0) goto cleanup;
    if(cur + fileHeader.SizeOfOptionalHeader > fileSize){
        printf("[!] Optional header truncated\n");
        goto cleanup;
    }

    printf("Number of sections: %u\n", fileHeader.NumberOfSections);
    printf("Size of optional header: %u\n", fileHeader.SizeOfOptionalHeader);

    printf("Machine: 0x%X\n", fileHeader.Machine);

    switch(fileHeader.Machine) {
        case 0x014c:
            printf("Architecture: x86\n");
            break;
        case 0x8664:
            printf("Architecture: x64\n");
            break;
        default:
            printf("Architecture: Unknown\n");
    }

    if (fileHeader.NumberOfSections == 0) {
        printf("Invalid PE: NumberOfSection is 0\n");
        goto cleanup;
    }else if(fileHeader.NumberOfSections > 96){
        printf("[!] Suspicious (rare), not invalid\n");
    }

    if (fileHeader.SizeOfOptionalHeader == 0) {
        printf("[!] Suspicious: no optional header\n");
    }

    if(fileHeader.SizeOfOptionalHeader < sizeof(uint16_t)){
        printf("[!] Optional header too small\n");
        goto cleanup;
    } 
    uint16_t magic;
    if(fread(&magic, sizeof(magic), 1, f) != 1){
        printf("Read Magic failed\n");
        goto cleanup;
    }
    if(fseek(f, -(long)sizeof(magic), SEEK_CUR) != 0){
        printf("Seek rewind magic failed\n");
        goto cleanup;
    }

    PE_OPTIONAL_COMMON common = {0};
    int is64;

    if(magic == 0x10B){
        printf("PE32 (32 bits)\n");
        IMAGE_OPTIONAL_HEADER32 opt32;
        is64 = 0;
       
        uint32_t toRead = fileHeader.SizeOfOptionalHeader;
        if(toRead > sizeof(IMAGE_OPTIONAL_HEADER32))
            toRead = sizeof(IMAGE_OPTIONAL_HEADER32);
        
        if(fread(&opt32, toRead, 1, f) != 1){
            printf("Read Optional header failed\n");
            goto cleanup;
        }
        common.ImageBase = opt32.ImageBase;
        common.AddressOfEntryPoint = opt32.AddressOfEntryPoint;
        common.Subsystem = opt32.Subsystem;
        common.DllCharacteristics = opt32.DllCharacteristics;
        common.SizeOfImage = opt32.SizeOfImage;
        common.NumberOfRvaAndSizes = opt32.NumberOfRvaAndSizes;
        common.SectionAlignment = opt32.SectionAlignment;
        if(common.NumberOfRvaAndSizes > 1){
            common.ImportRVA  = opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            common.ImportSize = opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        } 
        common.SizeOfHeaders = opt32.SizeOfHeaders;
        common.RelocRVA = opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        common.RelocSize = opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        if(common.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS){
            common.TlsRVA = opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
            common.TlsSize = opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
        }
    }else if(magic == 0x20B){
        printf("PE32+ (64 bits)\n");
        IMAGE_OPTIONAL_HEADER64 opt64;
        is64 = 1;
        
        uint32_t toRead = fileHeader.SizeOfOptionalHeader;
        if (toRead > sizeof(IMAGE_OPTIONAL_HEADER64))
            toRead = sizeof(IMAGE_OPTIONAL_HEADER64);
        if(fread(&opt64, toRead, 1, f) != 1){
            printf("Read Optional header failed\n");
            goto cleanup;
        }
        common.ImageBase = opt64.ImageBase;
        common.AddressOfEntryPoint = opt64.AddressOfEntryPoint;
        common.Subsystem = opt64.Subsystem;
        common.DllCharacteristics = opt64.DllCharacteristics;
        common.SizeOfImage = opt64.SizeOfImage;
        common.NumberOfRvaAndSizes = opt64.NumberOfRvaAndSizes;
        common.SectionAlignment = opt64.SectionAlignment;
        if(common.NumberOfRvaAndSizes > 1){
            common.ImportRVA  = opt64.DataDirectory[1].VirtualAddress;
            common.ImportSize = opt64.DataDirectory[1].Size;
        }
        common.SizeOfHeaders = opt64.SizeOfHeaders;
        common.RelocRVA = opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        common.RelocSize = opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        if(common.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS){
            common.TlsRVA = opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
            common.TlsSize = opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
        }
    }else{
        printf("Unknown optional header\n");
        goto cleanup;
    }

    if(common.AddressOfEntryPoint >= common.SizeOfImage){
        printf("[!] Suspicious: Original Entry Point(OEP) outside image\n");
    }
    printf("OEP: 0x%X\n", common.AddressOfEntryPoint);
    printf("Image base: 0x%llX\n",(unsigned long long)common.ImageBase);
    printf("Subsystem: ");
    switch(common.Subsystem){
        case 1:
            printf("Native\n");
            break;
        case 2:
            printf("Windows GUI\n");
            break;
        case 3:
            printf("Windows CUI(Terminal)\n");
            break;
        default:
            printf("Unknow\n");
            break;
    }
    if(!(common.DllCharacteristics & 0x40)){
        printf("[!] No ASLR\n");
    }
    if(!(common.DllCharacteristics & 0x100)){
        printf("[!] NX disabled\n");
    }
    
    if(common.SectionAlignment == 0){
        printf("[!] Invalid SectionAlignment\n");
        goto cleanup;
    }

    if(common.SizeOfImage % common.SectionAlignment != 0){
        printf("[!] Invalid SizeOfImage alignment!");
    }

    if(common.NumberOfRvaAndSizes < 16){
        printf("[!] Unsual number of data directories\n");
    }
    printf("Import Directory RVA: 0x%X\n",common.ImportRVA);
    printf("Import Directory Size: 0x%x\n",common.ImportSize);
    if(common.ImportRVA + common.ImportSize > common.SizeOfImage){
        printf("[!] Import directory outside image\n");
    }
    if(common.ImportRVA == 0 || common.ImportSize == 0){
        printf("[!] No import directory\n");
    }else if(common.ImportRVA >= common.SizeOfImage){
        printf("[!] Suspicious import RVA\n");
    }

    long sectionTableOffset = dos.e_lfanew + 4 + 
        sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader; 
    if((size_t)sectionTableOffset + (size_t)fileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > (size_t)fileSize){
            printf("[!] Section table truncated\n");
            goto cleanup;
        }
    
    if(fseek(f, sectionTableOffset,SEEK_SET) != 0){
        printf("Seek section table failed\n");
        goto cleanup;
    }
    sections = malloc(fileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    if(!sections){
        printf("Memory allocation failed\n");
        goto cleanup;
    }

    if(fread(sections, sizeof(IMAGE_SECTION_HEADER), fileHeader.NumberOfSections, f) != fileHeader.NumberOfSections){
        printf("Read section table failed\n");
        goto cleanup;
    }

    printf("\n=== Sections ===\n");
    for(int i = 0; i < fileHeader.NumberOfSections; i++){
        char name[9] = {0};
        memcpy(name, sections[i].Name, 8);

        printf("[%d] %s\n",i+1 , name);
        printf("    Virtual Address: 0x%X\n", (unsigned int)sections[i].VirtualAddress);
        printf("    Virtual Size: 0x%X\n", (unsigned int)sections[i].Misc.VirtualSize);
        printf("    Pointer To RawData: 0x%X\n", (unsigned int)sections[i].PointerToRawData);
        printf("    Size Of RawData: 0x%X\n", (unsigned int)sections[i].SizeOfRawData);
    }
    uint32_t importOffset;
    if(!rva_to_offset(common.ImportRVA,sections,fileHeader.NumberOfSections,&importOffset)){
        printf("[!] Failed to map Import RVA\n");
        goto cleanup;
    }
    printf("Import file offset: 0x%X\n",importOffset);
    fseek(f,importOffset, SEEK_SET);
    
    IMAGE_IMPORT_DESCRIPTOR desc;
    printf("\n=== Imports ===\n");
    while(1){
        if(fread(&desc, sizeof(desc), 1,f) != 1){
            printf("Read import descriptor failed\n");
            break;
        }

        if(desc.Name == 0){
            break;
        }
        uint32_t nameOffset;
        if (!rva_to_offset(desc.Name, sections, fileHeader.NumberOfSections, &nameOffset)) {
            printf("Failed to convert DLL name RVA\n");
            continue;
        }

        cur = ftell(f);
        fseek(f, nameOffset, SEEK_SET);

        char dllName[256];
        size_t i = 0;
        int c;

        while(i < sizeof(dllName) - 1 && (c = fgetc(f)) != EOF && c != '\0') {
            dllName[i++] = (char)c;
        }
        dllName[i] = '\0';

        printf("DLL: %s\n",dllName);
        
        fseek(f,cur, SEEK_SET);
    }
    printf("\n");

        imageMemory = VirtualAlloc(
        (LPVOID)(uintptr_t)common.ImageBase,
        common.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );

    if(!imageMemory){
        printf("[!] Allocate at preferred base failed, trying anywhere\n");

        imageMemory = VirtualAlloc(
            NULL,
            common.SizeOfImage,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
            );

        if(!imageMemory){
            printf("[!] VirtualAllocate failed\n");
            goto cleanup;
        }
    }

    printf("Allocated at: %p\n",imageMemory);

    rewind(f);
    headers = malloc(common.SizeOfHeaders);
    if(!headers){
        printf("Malloc failed\n");
        goto cleanup;
    }
    if(fread(headers, 1, common.SizeOfHeaders, f) != common.SizeOfHeaders){
        printf("Read headers failed\n");
        goto cleanup;
    }

    memcpy(imageMemory, headers, common.SizeOfHeaders);

    printf("\n=== Mapping Section ===\n");

    for(int i = 0; i < fileHeader.NumberOfSections; i++){
        uint8_t *dest = (uint8_t*)imageMemory + sections[i].VirtualAddress;
        uint32_t rawSize = sections[i].SizeOfRawData;
        uint32_t rawPtr = sections[i].PointerToRawData;
        uint32_t virtSize = sections[i].Misc.VirtualSize;

        printf("[%d] Mapping %.*s\n", i+1, 8, sections[i].Name);

        if(rawSize > 0){
            if(fseek(f, rawPtr, SEEK_SET) != 0){
                printf("[!] Seek to section raw failed\n");
                    goto cleanup;
                }

            buffer = malloc(rawSize);
            if(!buffer){
                printf("[!] malloc failed\n");
                goto cleanup;
            }
            if(fread(buffer, 1, rawSize, f) != rawSize){
                printf("[!] Read section raw failed\n");
                goto cleanup;
            }
            memcpy(dest, buffer, rawSize);
            free(buffer);
            buffer = NULL;
        }

        if(virtSize > rawSize){
            memset(dest + rawSize, 0, virtSize - rawSize);
        }
    }

    printf("\nOEP VA: %p\n", (uint8_t*)imageMemory + common.AddressOfEntryPoint);


    if(is64){
        relocation64(imageMemory, common.ImageBase, common.RelocRVA, common.RelocSize);
    }else{
        relocation32(imageMemory, common.ImageBase, common.RelocRVA, common.RelocSize);
    }
    if(!resolve_imports((uint8_t*)imageMemory, common.ImportRVA, is64)){
        printf("\n[!] Import resolution failed\n");
        goto cleanup;
    }
    
        section_Protections(imageMemory, sections, fileHeader.NumberOfSections);
    if(is64){
        runTLScallsbacks(imageMemory, common.TlsRVA, common, is64);
    }else{
        printf("\n[!] This PE Loader cannot run a 32 bits file\n");
    }

    status = 0;
    goto cleanup;
    cleanup:
        if (buffer) free(buffer);
        if (sections) free(sections);
        if (headers) free(headers);
        if (imageMemory) VirtualFree(imageMemory, 0, MEM_RELEASE);
        if (f) fclose(f);
        return status;

}
int rva_to_offset(uint32_t rva, IMAGE_SECTION_HEADER *section, uint16_t numSections, uint32_t *outOffset){
    for(int i = 0; i< numSections; i++){
        uint32_t va = section[i].VirtualAddress;
        uint32_t vs = section[i].Misc.VirtualSize;
        uint32_t rs = section[i].SizeOfRawData;
        uint32_t raw = section[i].PointerToRawData;

        uint32_t maxSize = vs > rs ? vs : rs;

        if (rva >= va && (rva - va) < maxSize) {
            if (raw == 0) return 0; 
            *outOffset = raw + (rva - va);
            return 1;
        }
    }
    return 0;
}
void relocation64(
        uint8_t *imageBase, 
        uint64_t preferredBase, 
        uint32_t relocRVA, 
        uint32_t relocSize 
){
    uintptr_t delta = (uintptr_t)imageBase - preferredBase; 
    if(delta == 0){
        printf("[*] No relocation needed\n");
        return;
    }

    if(relocSize == 0 || relocRVA == 0){
        printf("[!] No relocation directory\n");
        return;
    }

    IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION*)(imageBase + relocRVA);
    uint8_t *relocEnd = (uint8_t*)block + relocSize;
    int unknownCount = 0;

    while((uint8_t*)block < relocEnd && block->SizeOfBlock){
       uint32_t entryCount = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

       WORD *entry = (WORD*)(block +1 );

       for(uint32_t i = 0; i < entryCount; i++){
            uint16_t raw = *(entry + i);
            uint16_t type = raw >> 12;
            uint16_t offset = raw & 0x0FFF;
            
            if(type == IMAGE_REL_BASED_DIR64){
                uint64_t *patchAddr = (uint64_t*)(imageBase + block->VirtualAddress + offset);

                *patchAddr += delta;
            }else if(type == IMAGE_REL_BASED_ABSOLUTE){
            // ignore this case
            }else{
                unknownCount++;
            }
        }
        block = (IMAGE_BASE_RELOCATION*)((uint8_t*)block + block->SizeOfBlock);
    }
    if(unknownCount)
        printf("[!] Unknow relocation entries: %d\n",unknownCount);
    printf("[+] Relocation (64-bits) succeeded\n");
}void relocation32(
        uint8_t *imageBase, 
        uint32_t preferredBase, 
        uint32_t relocRVA, 
        uint32_t relocSize 
){
    uintptr_t delta = (uintptr_t)imageBase - preferredBase; 
    if(delta == 0){
        printf("[*] No relocation needed\n");
        return;
    }

    if(relocSize == 0 || relocRVA == 0){
        printf("[!] No relocation directory\n");
        return;
    }

    IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION*)(imageBase + relocRVA);
    uint8_t *relocEnd = (uint8_t*)block + relocSize;
    int unknownCount = 0;

    while((uint8_t*)block < relocEnd && block->SizeOfBlock){
       uint32_t entryCount = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

       WORD *entry = (WORD*)(block +1 );

       for(uint32_t i = 0; i < entryCount; i++){
            uint16_t raw = *(entry + i);
            uint16_t type = raw >> 12;
            uint16_t offset = raw & 0x0FFF;
            
            if(type == IMAGE_REL_BASED_DIR64){
                uint32_t *patchAddr = (uint32_t*)(imageBase + block->VirtualAddress + offset);

                *patchAddr += delta;
            }else if(type == IMAGE_REL_BASED_ABSOLUTE){
            // ignore this case
            }else{
                unknownCount++;
            }
        }
        block = (IMAGE_BASE_RELOCATION*)((uint8_t*)block + block->SizeOfBlock);
    }
    if(unknownCount)
        printf("[!] Unknow relocation entries: %d\n",unknownCount);
    printf("[+] Relocation (32-bits) succeeded\n");
}

int resolve_imports(
    uint8_t *imageBase,
    uint32_t importRVA,
    int is64
){
    printf("\n");
    if(importRVA == 0){
        printf("[!] No import directory\n");
        return 1;
    }
    IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR*)(imageBase + importRVA);
    
    if(is64){
        while(desc->Name){
            char *dllName = (char*)(imageBase + desc->Name);
        
            HMODULE hMod = LoadLibraryA(dllName);
            if(!hMod){
                printf("[!] LoadLibrary failed\n");
                return 0;
            }

            uint64_t *origThunk = NULL;
            uint64_t *firstThunk  = (uint64_t*)(imageBase + desc->FirstThunk);

            if(desc->OriginalFirstThunk){
                origThunk = (uint64_t*)(imageBase + desc->OriginalFirstThunk);
            }else{
                origThunk = firstThunk;
            }
            while(*origThunk){
            
                FARPROC func = NULL;

                if(IMAGE_SNAP_BY_ORDINAL(*origThunk)){
                    WORD ordinal = (IMAGE_ORDINAL(*origThunk));

                    func = GetProcAddress(hMod,MAKEINTRESOURCEA(ordinal));
                    printf("Ordinal: %u -> %p\n",ordinal, func);
                }else{
                    IMAGE_IMPORT_BY_NAME *name = (IMAGE_IMPORT_BY_NAME*)(imageBase + (*origThunk));

                    func = GetProcAddress(hMod,(LPCSTR)name->Name);
                    printf("%s -> %p\n", name->Name, func);
                }

                if(!func){
                    printf("[!] GetProcAddress failed\n");
                    return 1;
                }
                *firstThunk = (uint64_t)func;

                origThunk++;
                firstThunk++;
            }
            desc++;
        }
    }else{
        while(desc->Name){
            char *dllName = (char*)(imageBase + desc->Name);
        
            HMODULE hMod = LoadLibraryA(dllName);
            if(!hMod){
                printf("[!] LoadLibrary failed\n");
                return 0;
            }

            uint32_t *origThunk = NULL;
            uint32_t *firstThunk  = (uint32_t*)(imageBase + desc->FirstThunk);

            if(desc->OriginalFirstThunk){
                origThunk = (uint32_t*)(imageBase + desc->OriginalFirstThunk);
            }else{
                origThunk = firstThunk;
            }
            while(*origThunk){
            
                FARPROC func = NULL;

                if(IMAGE_SNAP_BY_ORDINAL(*origThunk)){
                    WORD ordinal = (IMAGE_ORDINAL(*origThunk));

                    func = GetProcAddress(hMod,MAKEINTRESOURCEA(ordinal));
                    printf("Ordinal: %u -> %p\n",ordinal, func);
                }else{
                    IMAGE_IMPORT_BY_NAME *name = (IMAGE_IMPORT_BY_NAME*)(imageBase + (*origThunk));

                    func = GetProcAddress(hMod,(LPCSTR)name->Name);
                    printf("%s -> %p\n", name->Name, func);
                }

                if(!func){
                    printf("[!] GetProcAddress failed\n");
                    return 1;
                }
                *firstThunk = (uint32_t)(uintptr_t)func;

                origThunk++;
                firstThunk++;
            }
            desc++;
        }
    }
    printf("[+] Import resolution complete\n");
    return 1;
}

DWORD SectionCharacteristicsToProtect(DWORD ch){
    BOOL executable = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
    BOOL readable = (ch & IMAGE_SCN_MEM_READ) != 0;
    BOOL writeable = (ch & IMAGE_SCN_MEM_WRITE) != 0;

    if(executable){
        if(writeable) return PAGE_EXECUTE_READWRITE;
        if(readable) return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    }else{
        if(writeable) return PAGE_READWRITE;
        if(readable) return PAGE_READONLY;
        return PAGE_NOACCESS;
    }
}

void section_Protections(
    uint8_t *imageBase,
    IMAGE_SECTION_HEADER *sections,
    uint16_t numSections
){
    printf("\n");
    for(uint16_t i = 0; i< numSections; i++){
        IMAGE_SECTION_HEADER *sec = sections + i;

        if(sec->SizeOfRawData == 0 && sec->Misc.VirtualSize == 0){
            continue;
        }

        uint8_t *secAddr = imageBase + sec->VirtualAddress;

        
        SIZE_T size = sec->Misc.VirtualSize >= sec->SizeOfRawData ? sec->Misc.VirtualSize:sec->SizeOfRawData;

        DWORD newProtect = SectionCharacteristicsToProtect(sec->Characteristics);
        DWORD oldProtect = 0;

        if(!VirtualProtect(secAddr, size, newProtect, &oldProtect)){
            printf("[!] VirtualProtect Failed on section %.8s (err=%lu)\n", sec->Name, GetLastError());
        }else{
            printf("[+] Protect section %.8s -> 0x%lX\n", sec->Name, newProtect);
        }
    }   
}
void runTLScallsbacks(uint8_t *imageBase, uint32_t tlsRVA, PE_OPTIONAL_COMMON common, int is64) {
    if (!tlsRVA) return;

    uint64_t addrOfCallbacks = 0;
    if(is64){
        IMAGE_TLS_DIRECTORY64 *tls64 = (IMAGE_TLS_DIRECTORY64*)(imageBase + tlsRVA);
        addrOfCallbacks = tls64->AddressOfCallBacks;
    }else{
        IMAGE_TLS_DIRECTORY32 *tls32 = (IMAGE_TLS_DIRECTORY32*)(imageBase + tlsRVA);
        addrOfCallbacks = tls32->AddressOfCallBacks;
    }

    if (!addrOfCallbacks) return;

    void *currentCallbackEntry = VaToPtr(addrOfCallbacks, common.ImageBase, imageBase, common.SizeOfImage);
    if(!currentCallbackEntry) return;

    if(is64){
        while(1){
            uint64_t funcVA = 0;

            funcVA = *(uint64_t*)currentCallbackEntry;

            if(funcVA == 0) break;

            void (*cb)(PVOID, DWORD, PVOID) = (void (*)(PVOID, DWORD, PVOID))VaToPtr(
                funcVA, common.ImageBase, imageBase, common.SizeOfImage
            );

            if(cb){
                printf("[+] Executing TLS Callback at: 0x%" PRIx64 "\n",funcVA);
                cb(imageBase, DLL_PROCESS_ATTACH, NULL);
            }
        
            currentCallbackEntry = (uint8_t*)currentCallbackEntry + 8;
        }
    }else{
        while(1){
            uint32_t funcVA = 0;

            funcVA = *(uint32_t*)currentCallbackEntry;

            if(funcVA == 0) break;

            void (*cb)(PVOID, DWORD, PVOID) = (void (*)(PVOID, DWORD, PVOID))VaToPtr(
                funcVA, common.ImageBase, imageBase, common.SizeOfImage
            );

            if(cb){
                printf("[+] Executing TLS Callback at: 0x%u\n",funcVA);
                cb(imageBase, DLL_PROCESS_ATTACH, NULL);
            }
        
            currentCallbackEntry = (uint8_t*)currentCallbackEntry + 4;
        }
    }
}
void* VaToPtr(uint64_t va, uint64_t imageBase, uint8_t* mappedBase, uint32_t sizeOfImage){
    if(va < imageBase)
        return NULL;

    uint64_t offset = va - imageBase;

    if(offset >= sizeOfImage)
        return NULL;

    return mappedBase + offset;
}
