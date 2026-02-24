#include <stdio.h>
#include <stdint.h>

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
        fclose(f);
        return 1;
    }
    
    if(dos.e_magic != 0x5A4D){
        printf("%s is not PE\n", argv[1]);
        return 0;
    }

    if(fseek(f, dos.e_lfanew, SEEK_SET) != 0){
        printf("Seek failed");
        fclose(f);
        return 1;
    }

    uint32_t pe_sig;
    if(fread(&pe_sig, sizeof(pe_sig), 1, f) != 1){
         printf("Read PE signature failed\n");
         fclose(f);
         return 1;
    }

    if(pe_sig == 0x00004550){
        printf("%s Valid PE\n", argv[1]);
    }else{
        printf("%s Invalid PE\n", argv[1]);
        fclose(f);
        return 1;
    }
    
    IMAGE_FILE_HEADER fileHeader;

    if (fread(&fileHeader, sizeof(fileHeader), 1, f) != 1) {
        printf("Read FILE_HEADER failed\n");
        fclose(f);
        return 1;
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
    }

    if (fileHeader.SizeOfOptionalHeader == 0) {
        printf("[!] Suspicious: no optional header\n");
    }


    uint32_t sectionOffset = dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
    printf("Section table offset :0x%X\n",(unsigned int)sectionOffset);
    if(fseek(f, sectionOffset, SEEK_SET) != 0){
        printf("Seek section table offset failed\n");
        fclose(f);
        return 1;
    }

    fclose(f);
    return 0;
}
