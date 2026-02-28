#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

void failToReadOrSeek(FILE *f);

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
#pragma pack(pop)

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
        failToReadOrSeek(f); 
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
        failToReadOrSeek(f);
    }

    if(fseek(f, dos.e_lfanew, SEEK_SET) != 0){
        printf("Seek failed");
        failToReadOrSeek(f);
    }
;
    uint32_t pe_sig;
    if(fread(&pe_sig, sizeof(pe_sig), 1, f) != 1){
        printf("Read PE signature failed\n");
        failToReadOrSeek(f);
    }

    if(pe_sig == 0x00004550){
        printf("%s Valid PE\n", argv[1]);
    }else{
        printf("%s Invalid PE\n", argv[1]);
        failToReadOrSeek(f);
    }
    
    IMAGE_FILE_HEADER fileHeader;
    if (fread(&fileHeader, sizeof(fileHeader), 1, f) != 1) {
        printf("Read FILE_HEADER failed\n");
        failToReadOrSeek(f);
    }

    long long cur = ftell(f);
    if(cur + fileHeader.SizeOfOptionalHeader > fileSize){
        printf("[!] Optional header truncated\n");
        failToReadOrSeek(f);
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
        failToReadOrSeek(f);
    } 
    uint16_t magic;
    if(fread(&magic, sizeof(magic), 1, f) != 1){
        printf("Read Magic failed\n");
        failToReadOrSeek(f);
    }
    if(fseek(f, -sizeof(magic), SEEK_CUR) != 0){
        printf("Seek rewind magic failed\n");
        failToReadOrSeek(f);
    }

    if(magic == 0x10B){
        printf("PE32 (32 bits)\n");
        IMAGE_OPTIONAL_HEADER32 opt32;
       
        uint32_t toRead = fileHeader.SizeOfOptionalHeader;
        if(toRead > sizeof(IMAGE_OPTIONAL_HEADER32))
            toRead = sizeof(IMAGE_OPTIONAL_HEADER32);
        
        if(fread(&opt32, toRead, 1, f) != 1){
            printf("Read Optional header failed\n");
            failToReadOrSeek(f);
        }
    }else if(magic == 0x20B){
        printf("PE32+ (64 bits)\n");
        IMAGE_OPTIONAL_HEADER64 opt64;
        
        uint32_t toRead = fileHeader.SizeOfOptionalHeader;
        if (toRead > sizeof(IMAGE_OPTIONAL_HEADER64))
            toRead = sizeof(IMAGE_OPTIONAL_HEADER64);
        if(fread(&opt64, toRead, 1, f) != 1){
            printf("Read Optional header failed\n");
            failToReadOrSeek(f);
        }
    }else{
        printf("Unknown optional header\n");
    }

    fclose(f);
    return 0;

}
void failToReadOrSeek(FILE *f){
    if(f != NULL)
        fclose(f);
    exit(1);
}
