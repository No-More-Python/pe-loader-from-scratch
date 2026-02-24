#include <stdio.h>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct{
    uint16_t e_magic;
    uint8_t padding[58];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER;
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
        printf("Read Error\n");
        fclose(f);
        return 1;
    }
    
    if(dos.e_magic != 0x5A4D){
        printf("%s is not PE\n", argv[1]);
        return 0;
    }

    if(fseek(f, dos.e_lfanew, SEEK_SET)){
        printf("Seek failed");
        fclose(f);
        return 1;
    }

    uint32_t pe_sig;
    fread(&pe_sig, sizeof(pe_sig), 1, f);

    if(pe_sig == 0x00004550){
        printf("%s Valid PE\n", argv[1]);
    }else{
        printf("%s Invalid PE\n", argv[1]);
        fclose(f);
        return 1;
    }

    fclose(f);
}
