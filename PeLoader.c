#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#pragma pack(push, 1)
// 64 Bytes
typedef struct{
    uint16_t e_magic;
    uint8_t padding[58];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER;

// 20 Bytes
typedef struct{
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct{
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

// 224 Bytes
typedef struct{
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32;

// 240 Bytes
typedef struct {
    uint16_t  Magic;                      
    uint8_t   MajorLinkerVersion;
    uint8_t   MinorLinkerVersion;
    uint32_t  SizeOfCode;
    uint32_t  SizeOfInitializedData;
    uint32_t  SizeOfUninitializedData;
    uint32_t  AddressOfEntryPoint;
    uint32_t  BaseOfCode;
    uint64_t  ImageBase;
    uint32_t  SectionAlignment;
    uint32_t  FileAlignment;
    uint16_t  MajorOperatingSystemVersion;
    uint16_t  MinorOperatingSystemVersion;
    uint16_t  MajorImageVersion;
    uint16_t  MinorImageVersion;
    uint16_t  MajorSubsystemVersion;
    uint16_t  MinorSubsystemVersion;
    uint32_t  Win32VersionValue;
    uint32_t  SizeOfImage;
    uint32_t  SizeOfHeaders;
    uint32_t  CheckSum;
    uint16_t  Subsystem;
    uint16_t  DllCharacteristics;
    uint64_t  SizeOfStackReserve;           
    uint64_t  SizeOfStackCommit;            
    uint64_t  SizeOfHeapReserve;          
    uint64_t  SizeOfHeapCommit;           
    uint32_t  LoaderFlags;
    uint32_t  NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16]; 
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
    uint8_t Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;
#pragma pack(pop)

typedef struct {
    uint64_t ImageBase;
    uint32_t AddressOfEntryPoint;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfImage;
    uint32_t NumberOfRvaAndSizes;
    uint32_t SectionAlignment;
    uint32_t ImportRVA;
    uint32_t ImportSize;
} PE_OPTIONAL_COMMON;

void mistakeOccured(FILE *f);
int rva_to_offset(uint32_t rva, IMAGE_SECTION_HEADER *section, uint16_t numSections,uint32_t *outOffset);

int main(int argc,char **argv){
    if(argc < 2){
        printf("Usage : %s <Filename>\n", argv[0]);
        return 1;
    }
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    IMAGE_DOS_HEADER dos;

    if(fread(&dos, sizeof(dos), 1, f) != 1){
        if(feof(f)){
            printf("File too small to be a PE file\n");
        }else{
            printf("Read error\n");
        }
        mistakeOccured(f); 
    }
    
    if(dos.e_magic != 0x5A4D){
        printf("%s is not PE\n", argv[1]);
        return 0;
    }
    fseek(f, 0, SEEK_END);
    long long fileSize = ftell(f);
    rewind(f);
    if(dos.e_lfanew > fileSize - (4 + sizeof(IMAGE_FILE_HEADER))){
        printf("[!] File is too small to contain a valid PE header\n");
        mistakeOccured(f);
    }

    if(fseek(f, dos.e_lfanew, SEEK_SET) != 0){
        printf("Seek failed");
        mistakeOccured(f);
    }
    uint32_t pe_sig;
    if(fread(&pe_sig, sizeof(pe_sig), 1, f) != 1){
        printf("Read PE signature failed\n");
        mistakeOccured(f);
    }

    if(pe_sig == 0x00004550){
        printf("%s Valid PE\n", argv[1]);
    }else{
        printf("%s Invalid PE\n", argv[1]);
        mistakeOccured(f);
    }
    
    IMAGE_FILE_HEADER fileHeader;
    if (fread(&fileHeader, sizeof(fileHeader), 1, f) != 1) {
        printf("Read FILE_HEADER failed\n");
        mistakeOccured(f);
    }

    long long cur = ftell(f);
    if(cur + fileHeader.SizeOfOptionalHeader > fileSize){
        printf("[!] Optional header truncated\n");
        mistakeOccured(f);
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
        printf("[!] Suspicious: zero sections\n");
    }else if(fileHeader.NumberOfSections > 96){
        printf("[!] Suspicious (rare), not invalid\n");
    }

    if (fileHeader.SizeOfOptionalHeader == 0) {
        printf("[!] Suspicious: no optional header\n");
    }

    if(fileHeader.SizeOfOptionalHeader < sizeof(uint16_t)){
        printf("[!] Optional header too small\n");
        mistakeOccured(f);
    } 
    uint16_t magic;
    if(fread(&magic, sizeof(magic), 1, f) != 1){
        printf("Read Magic failed\n");
        mistakeOccured(f);
    }
    if(fseek(f, -sizeof(magic), SEEK_CUR) != 0){
        printf("Seek rewind magic failed\n");
        mistakeOccured(f);
    }

    PE_OPTIONAL_COMMON common = {0};

    if(magic == 0x10B){
        printf("PE32 (32 bits)\n");
        IMAGE_OPTIONAL_HEADER32 opt32;
       
        uint32_t toRead = fileHeader.SizeOfOptionalHeader;
        if(toRead > sizeof(IMAGE_OPTIONAL_HEADER32))
            toRead = sizeof(IMAGE_OPTIONAL_HEADER32);
        
        if(fread(&opt32, toRead, 1, f) != 1){
            printf("Read Optional header failed\n");
            mistakeOccured(f);
        }
        common.ImageBase = opt32.ImageBase;
        common.AddressOfEntryPoint = opt32.AddressOfEntryPoint;
        common.Subsystem = opt32.Subsystem;
        common.DllCharacteristics = opt32.DllCharacteristics;
        common.SizeOfImage = opt32.SizeOfImage;
        common.NumberOfRvaAndSizes = opt32.NumberOfRvaAndSizes;
        common.SectionAlignment = opt32.SectionAlignment;
        if(common.NumberOfRvaAndSizes > 1){
            common.ImportRVA  = opt32.DataDirectory[1].VirtualAddress;
            common.ImportSize = opt32.DataDirectory[1].Size;
        } 
    }else if(magic == 0x20B){
        printf("PE32+ (64 bits)\n");
        IMAGE_OPTIONAL_HEADER64 opt64;
        
        uint32_t toRead = fileHeader.SizeOfOptionalHeader;
        if (toRead > sizeof(IMAGE_OPTIONAL_HEADER64))
            toRead = sizeof(IMAGE_OPTIONAL_HEADER64);
        if(fread(&opt64, toRead, 1, f) != 1){
            printf("Read Optional header failed\n");
            mistakeOccured(f);
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
    }else{
        printf("Unknown optional header\n");
        mistakeOccured(f);
    }

    if(common.AddressOfEntryPoint >= common.SizeOfImage){
        printf("[!] Suspicious: Original Entry Point(OEP) outside image\n");
    }
    printf("OEP: 0x%X\n", common.AddressOfEntryPoint);
    printf("Image base: 0x%I64X\n",(unsigned long long)common.ImageBase);
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
        mistakeOccured(f);
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
    if(sectionTableOffset + (long)fileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > fileSize){
            printf("[!] Section table truncated\n");
            mistakeOccured(f);
        }
    
    if(fseek(f, sectionTableOffset,SEEK_SET) != 0){
        printf("Seek section table failed\n");
        mistakeOccured(f);
    }
    IMAGE_SECTION_HEADER *sections = malloc(fileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    if(!sections){
        printf("Memory allocation failed\n");
        mistakeOccured(f);
    }

    if(fread(sections, sizeof(IMAGE_SECTION_HEADER), fileHeader.NumberOfSections, f) != fileHeader.NumberOfSections){
        printf("Read section table failed\n");
        free(sections);
        mistakeOccured(f);
    }

    printf("\n=== Sections ===\n");
    for(int i = 0; i < fileHeader.NumberOfSections; i++){
        char name[9] = {0};
        memcpy(name, sections[i].Name, 8);

        printf("[%d] %s\n",i+1 , name);
        printf("    Virtual Address: 0x%X\n", sections[i].VirtualAddress);
        printf("    Virtual Size: 0x%X\n", sections[i].Misc.VirtualSize);
        printf("    Pointer To RawData: 0x%X\n", sections[i].PointerToRawData);
        printf("    Size Of RawData: 0x%X\n", sections[i].SizeOfRawData);
    }
    uint32_t importOffset;
    if(rva_to_offset(common.ImportRVA,sections,fileHeader.NumberOfSections,&importOffset)){
        printf("Import file offset: 0x%X\n",importOffset);
    }else{
        printf("[!] Failed to map Import RVA\n");
    }


    fclose(f);
    return 0;

}
void mistakeOccured(FILE *f){
    if(f != NULL)
        fclose(f);
    exit(1);
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
