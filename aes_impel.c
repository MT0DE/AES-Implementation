#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static FILE *inputfile;
static FILE *outputfile;

void binaryToHex(unsigned char bytes[], int byte_size, char *hex);
void encrypt_block(unsigned char key[], unsigned char block[], char *outputblock);

int main(int argc, char const *argv[])
{
    if(argc == 1){
        printf("Error: needs an (1) input file");
        return 1;
    }

    inputfile = fopen(argv[1],"rb");    
    if(inputfile == NULL){
        printf("Error: could not open file");
        return 1;
    }

    unsigned char block[16];
    unsigned char key[16];
    short keySize = 16; // key is 16 bytes
    unsigned char c;
    int counter = 0;

    //Read in key
    while (counter < keySize)
    {
        //c is one byte
        c = (unsigned char) fgetc(inputfile);
        // printf("Counter: %d, num: %d\n", counter, c);
        key[counter++] = c;
    }

    // outputfile = fopen("output.ans", "w");
    //Stream in 16 bytes at a time and encrypt/decrypt each block separatley
    // while(feof(inputfile) == 0){
    //     counter = 0;
    //     while(counter < keySize){
    //         c = fgetc(inputfile);
    //         block[counter++] = c;
    //     }
    //     // encrypt/decrypt
    //     char changedBlock[16]; 
    //     encrypt_block(key, block, changedBlock);

    //     fwrite(changedBlock, sizeof(changedBlock), 1, outputfile);
    // }
    
    int keyLength = sizeof(key)/sizeof(key[0]);
    printf("Key-lenght: %d\n", keyLength);

    char keyHex[keyLength*2];
    binaryToHex(key, keyLength, keyHex);
    printf("Key in Hex: %s",keyHex);
    // printf("Read block: %d", sizeof(key)/sizeof(key[0]));

    fclose(inputfile);
    // fclose(outputfile);
    
    return 0;
}

void binaryToHex(unsigned char bytes[], int byte_size, char *hex){
    char hexabeth[] = "0123456789ABCDEF";
    unsigned char left, right;
    int bin_len = byte_size;
    char temp[bin_len*2 + 1];
    for (int i = 0; i < bin_len; i++)
    {
        //0b01101010
        unsigned char c = bytes[i];

        //0b00000110
        left = c >> 4; 
        
        //0b00001010
        right = c & 0xf;

        // printf("#%d c:%x, left:%x, right:%x\n", i, c, left, right);
        temp[2*i] = hexabeth[left];
        temp[2*i+1] = hexabeth[right];
    }

    //NULL terminate the string or else
    temp[bin_len*2-1] = '\0';
    memcpy(hex, temp, bin_len*2);
}

void encrypt_block(unsigned char key[], unsigned char block[], char *outputblock){
    
}
