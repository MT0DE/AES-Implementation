#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static FILE *inputfile;
static FILE *outputfile;

void binaryToHex(unsigned char bytes[], int byte_size, char *hex);
void encrypt_block(unsigned char key[], unsigned char block[], int blockSize);

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
    //     encrypt_block(key, block, 16);
    //     // block is now encrypted 
    //     fwrite(block, sizeof(block), 1, outputfile);
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

void encrypt_block(unsigned char key[], unsigned char block[], int blockSize){
    int rounds = 10;

    unsigned char word1[4],word2[4],word3[4],word4[4];
    unsigned char *state = block;
    
    for (int i = 0; i < 4; i++)
    {
        word1[i] = block[i];
        word2[i] = block[i+1];
        word3[i] = block[i+2];
        word4[i] = block[i+3];
    }
    
    //Use 0th (given) Roundkey on state
    //
    for (int i = 0; i < rounds-1; i++)
    {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, key); //we updated the Key and apply the key here
    }

    //last round, no mix-columns
    subBytes(state);
    shiftRows(state);
    addRoundKey(state);

    //FINISHED, state has now changed the original block
}
