/*
 *  Autor: speed_com
Program ktory wypisuje podstawowe informacje o wskazanym
pliku PE, takie jak:
 - adres naglowka PE
 - ilosc sekcji
 - nazwy wszystkich sekcji
 - subsystem
 - EP
 - adres na ktory PE chce byc zaladowany w pamieci (ImageBase)
*/


// Includes
#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include <stdlib.h>


// Function declarations
static unsigned char * FileGetContent(const char *FileName,  size_t *Size);


//
// MAIN
//
int
main(int argc, char **argv) {


    // Load the file into memory
    unsigned char * data;
    size_t s;
    data = FileGetContent(argv[1], &s);
    if(data == NULL) {
        fprintf(stderr, "file not found\n");
        return 1;
    }


    // Check if this is a PE file
    if(*(short *)data != *(short *)"MZ") {
        puts("To nie jest plik PE\n");
        return 2;
    }
    // HEADERS
    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)data;
    IMAGE_NT_HEADERS *NtHeaders = (IMAGE_NT_HEADERS *)(data + DosHeader->e_lfanew);
    IMAGE_SECTION_HEADER *SectionHeader = (IMAGE_SECTION_HEADER *)(data + DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
     
    // INFORMATION OUTPUT
    int i;
    printf("Adres naglowka PE: 0x%lx\n", DosHeader->e_lfanew);
    printf("Ilosc sekcji: %d\n", i = NtHeaders->FileHeader.NumberOfSections);
    
    while(i-- > 0) {
             printf("Nazwa sekcji: %s\n", SectionHeader++->Name);                       
    }
    
    printf("Adres wejscia (EP): 0x%x\n", NtHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("ImageBase: 0x%x\n", NtHeaders->OptionalHeader.ImageBase);
    printf("Subsystem: %d\n", NtHeaders->OptionalHeader.Subsystem);
    
    
    return 0;
}
//
// FileGetContent
//
static unsigned char * 
FileGetContent(const char *FileName,  size_t *Size) {


    // Some variables
    FILE *f;
    size_t FileSize;
     unsigned char *Data;
    
    // Open the file
    f = fopen(FileName, "rb");
    if(!f) return NULL;
    
    // Get file size
    fseek(f, 0, SEEK_END);
    FileSize = ftell(f);
    fseek(f, 0, SEEK_SET);


    // Allocate memory
    Data = (unsigned char *)malloc(FileSize+1);
    if(!Data) {
        fclose(f);
        return NULL;    
    }


    // Read file content
    FileSize = fread(Data, 1, FileSize, f);
    Data[FileSize] = 0;


    // Close the file
    fclose(f);


    // Return
    if(Size) // Size is optional
        *Size = FileSize;
    return Data;
}