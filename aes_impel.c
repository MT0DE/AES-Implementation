#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static const unsigned char sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const unsigned char Rcon[11] ={0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

//Depends on AES version (128bit = 4, 196bit = 6, 256bit = 8)
#define Nk 4
//Depends on AES version (128bit = 10, 196bit = 12, 256bit = 14)
#define Nr 10
//Is always 4
#define Nb 4 
#define maxBytes 1600000

//I decided to use bytes instead of words so I increased the keySchedule array 4 times since one word is 4 bytes
// it would hold the same amount of information anyways so not to disturb any "performance"
static unsigned char keySchedule[Nb *(Nr + 1)*4];
static unsigned char blocks[maxBytes];
int keyCont = 0; 

void binaryToHex(unsigned char bytes[], int byte_size);
void hexToBinary(char *hex, int hexKardinality, unsigned char *bytes);
void encrypt_block(unsigned char block[], int blockSize);
void shiftRows(unsigned char *block);
void mixColumns(unsigned char *block);
void keyExpansion(unsigned char key[], unsigned char keySchedule[]);


int main(int argc, char const *argv[])
{
    // if(argc == 1){
    //     printf("Error: needs an (1) input file");
    //     return 1;
    // }
    unsigned char block[16];
    unsigned char key[16];
    
    printf("START");
    FILE* inputfile = fopen("aes_sample.in", "r");
    //Read in key
    int counter = 0;
    // counter = read(STDIN_FILENO, key, 16);
    hexToBinary("F4C020A0A1F604FD343FAC6A7E6AE0F9", 32, key);

    // Create KeySchedule from key
    keyExpansion(key, keySchedule);
    // printKeyExpansion();
    
    //Stream in 16 bytes at a time and encrypt/decrypt each block separatley
    int totalBytes= 0;
    short flag = 1;
    int blocksCounter = 0;
    int amountWriteBack = 0;
    counter = 1;

    printf("START");
    int start = clock();
    while (1)
    {
        // while((counter = read(STDIN_FILENO, blocks, maxBytes)) != EOF)
        while((counter = fread(blocks, sizeof(blocks), 1, inputfile)) != EOF){
            amountWriteBack = counter;
            blocksCounter = 0;
            while (counter > 0)
            {
                // Retrive one block from blocks
                for (size_t i = 0; i < Nk*4; i++)
                {
                    block[i] = blocks[blocksCounter++];
                }
                
                // Encrypt block
                encrypt_block(block, 16);
                blocksCounter -= 16;
                for (size_t i = 0; i < Nk*4; i++)
                {
                    blocks[blocksCounter++] = block[i];
                }
                counter -= 16;
            }
            if(amountWriteBack == maxBytes){
                // Write the entire "blocks" once it is encrypted 
                write(STDOUT_FILENO, blocks, maxBytes);
            }
            else{ 
                write(STDOUT_FILENO, blocks, amountWriteBack);
            }
        }
        if(counter == -1){
            break;
        }
    }
    int end = clock();
    printf("It took %.2f second(s) to encrypt 1 000 000 times",(float)((end-start)/CLOCKS_PER_SEC));
    
    
    
    // hexToBinary("F295B9318B994434D93D98A4E449AFD8", 32, block);
    // int start = clock();
    // for (size_t i = 0; i < 1000000; i++)
    // {
    //     encrypt_block(block, 16);
    // }
    // int end = clock();

    


    // printf("Encrypted block: ");
    // binaryToHex(block, 16);
    // int keyLength = sizeof(key)/sizeof(key[0]);
    // char keyHex[keyLength*2 + 1];
    // __uint8_t back2Binary[keyLength];
    // binaryToHex(key, keyLength, keyHex);
    // hexToBinary(keyHex, keyLength*2, back2Binary);
    
    // printf("Key in Hex: \n%s\n",keyHex);
    
    return 0;
}

void binaryToHex(unsigned char bytes[], int byte_size){
    for (int i = 0; i < byte_size; i++)
    {
       printf("%02x", bytes[i]);
    }
    puts("");
}

void hexToBinary(char *hex, int hexKardinality, __uint8_t *bytes){
    char hexabeth[] = "0123456789ABCDEF";
    for (size_t i = 0; i < hexKardinality; i += 2)
    {
        unsigned char left, right;
        if(hex[i] >= 'A' && hex[i+1] >= 'A'){
            left = hex[i] - 'A' + 10;
            right = hex[i+1] - 'A' + 10;
        }
        else if(hex[i] < 'A' && hex[i+1] >= 'A'){
            left = hex[i] - '0';
            right = hex[i+1] - 'A' + 10;
        }
        else if(hex[i] >= 'A' && hex[i+1] < 'A'){
            left = hex[i] - 'A' + 10;
            right = hex[i+1] - '0';
        }
        else{
            left = hex[i] - '0';
            right = hex[i+1] - '0';
        }
        bytes[i/2] = left << 4 | right;
    }
}

void subBytes(unsigned char *block, int blockSize){
    for (int i = 0; i < blockSize; i++)
    {
        block[i] = sbox[block[i]];
    }
}

/* 
            1  2  3  4       1  2  3  4
Block -->   5  6  7  8   --> 6  7  8  5
            9  10 11 12      11 12 9  10
            13 14 15 16      16 13 14 15
*/
void shiftRows(unsigned char *block){
    
    unsigned char temp[2];
    //1th row clear

    // 0  1  2  3       0  5  10 15 
    // 4  5  6  7  -->  4  9  14 3
    // 8  9  10 11      8  13 2  7
    // 12 13 14 15      12 1  6  11

    //2nd row
    temp[0] = block[1];
    size_t i;
    block[1] = block[5];
    block[5] = block[9];
    block[9] = block[13];
    block[13] = temp[0];

    // 3rd row
    temp[0] = block[2];
    temp[1] = block[6];
    block[2] = block[10];
    block[6] = block[14];
    block[10] = temp[0];
    block[14] = temp[1];

    // 4th row
    temp[0] = block[15];
    block[15] = block[11];
    block[11] = block[7];
    block[7] = block[3];
    block[3] = temp[0];
}


//Inspired and described by FIPS 197, checks whether  
//the irreduciable polynomial theorem needs to be used 
unsigned char xtime(unsigned char byte){
    return (byte << 1 ^ (((byte >> 7) & 1) * 0x1b));
}

unsigned char gfMulti(unsigned char byte, int term){
    if(term == 1){
        return byte;
    }
    //check if polynomial is over the limit
    //adjust with irreduciable polynomial theorem, as needed
    __uint8_t copy = byte;
    __uint8_t shifted = xtime(byte);
    if (term == 3)
    {
        return shifted ^ copy;
    }
    return shifted;
}

void mixColumns(unsigned char *block){
    unsigned char copy_block[Nk*4];
    for (size_t i = 0; i < Nk*4; i++)
    {
        copy_block[i] = block[i];
    }
    
    for (int i = 0; i < Nk; i++)
    {
        block[4*i]   = gfMulti(copy_block[4*i], 0x02) ^ gfMulti(copy_block[4*i+1], 0x03) ^ copy_block[4*i+2] ^ copy_block[4*i+3];
        block[4*i+1] = copy_block[4*i] ^ gfMulti(copy_block[4*i+1], 0x02) ^ gfMulti(copy_block[4*i+2], 0x03) ^ copy_block[4*i+3];
        block[4*i+2] = copy_block[4*i] ^ copy_block[4*i+1] ^ gfMulti(copy_block[4*i+2], 0x02) ^ gfMulti(copy_block[4*i+3], 0x03);
        block[4*i+3] = gfMulti(copy_block[4*i], 0x03) ^ gfMulti(copy_block[4*i+3], 0x02) ^ copy_block[4*i+1] ^ copy_block[4*i+2];
    }
    
}

void addRoundKey(unsigned char *block, int blockSize){
    unsigned char RoundKey[16];
    
    // Assign key to be i:th Round key
    for (int i = 0; i < Nk; i++)
    {
        //keyCont is a global variable
        RoundKey[4*i] = keySchedule[keyCont];
        RoundKey[4*i+1] = keySchedule[keyCont+1];
        RoundKey[4*i+2] = keySchedule[keyCont+2];
        RoundKey[4*i+3] = keySchedule[keyCont+3];
        keyCont += 4;
    }

    //XOR State with i:th Roundkey
    __uint8_t roundkey_index = 0;
    for (int i = 0; i < 4; i++)
    {
        block[4*i] = block[4*i] ^ RoundKey[roundkey_index];
        block[4*i+1] = block[4*i+1] ^ RoundKey[roundkey_index+1];
        block[4*i+2] = block[4*i+2] ^ RoundKey[roundkey_index+2];
        block[4*i+3] = block[4*i+3] ^ RoundKey[roundkey_index+3];
        roundkey_index += 4;
    }
}

void RotWord(unsigned char *word){
    unsigned char temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

void keyExpansion(unsigned char key[], unsigned char keySchedule[]){
    // // "temp" Keeps 4 bytes (word) temporarily
    // // "keySchedule" is an array of bytes (because less headache)
    unsigned char temp[4];
    int keylenght = 4*Nk;
    int i = 0;

    while (i < keylenght)
    {
        keySchedule[i] = key[i];
        i++;
    }
        
    i = keylenght;
    while (i < (Nb*(Nr+1))*4)
    {
        //load previous word
        temp[0] = keySchedule[(i-4)];
        temp[1] = keySchedule[(i-3)];
        temp[2] = keySchedule[(i-2)];
        temp[3] = keySchedule[(i-1)];

        if(i % keylenght == 0){
            RotWord(temp);
            subBytes(temp, 4);
            temp[0] = temp[0] ^ Rcon[i/keylenght];            
        }
        //Only for 256bit AES
        else if ((keylenght > 20) && (i % keylenght == 16)){
            subBytes(temp, 4);
        }
        //create new word from start and end of previous key
        keySchedule[i]   = keySchedule[i-keylenght]   ^ temp[0];
        keySchedule[i+1] = keySchedule[i+1-keylenght] ^ temp[1];
        keySchedule[i+2] = keySchedule[i+2-keylenght] ^ temp[2];
        keySchedule[i+3] = keySchedule[i+3-keylenght] ^ temp[3];
        // printf("tempe = %x %x %x %x\n", keySchedule[i], keySchedule[i+1], keySchedule[i+2], keySchedule[i+3]);
        i += 4;
    }
}

void encrypt_block(unsigned char block[], int blockSize){
    unsigned char *state = block;
    keyCont = 0; //must be reset or else
    
    //Use 0th Roundkey (given) on state
    addRoundKey(state, blockSize); 
    
    //Start the rounds-1
    for (int i = 0; i < Nr-1; i++)
    {
        subBytes(state, blockSize);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, blockSize); //we updated the Key and apply the key here
    }

    //last round, no mix-columns
    subBytes(state, blockSize);
    shiftRows(state);
    addRoundKey(state, blockSize);

    //FINISHED, state has now changed the original block
}

void testMixColumns(){
    __uint8_t bytes[16];
    hexToBinary("87F24D976E4C90EC46E74AC3A68CD895", 32, bytes);
    for (size_t i = 0; i < 16; i++)
    {
        if (i % 4 == 0)
        {
            printf("\n");
        }
        printf("%x ", bytes[i]);
        
    }
    printf("\n");
    mixColumns(bytes);
    for (size_t i = 0; i < 16; i++)
    {
        if (i % 4 == 0)
        {
            printf("\n");
        }
        printf("%x ", bytes[i]);
        
    }
}

void printKeyExpansion(){
    __uint8_t byte[16];
    for (int i = 0; i < Nb*(Nr+1)*4; i += 16)
    {
        byte[0] = keySchedule[i];
        byte[1] = keySchedule[i+1];
        byte[2] = keySchedule[i+2];
        byte[3] = keySchedule[i+3];
        byte[4] = keySchedule[i+4];
        byte[5] = keySchedule[i+5];
        byte[6] = keySchedule[i+6];
        byte[7] = keySchedule[i+7];
        byte[8] = keySchedule[i+8];
        byte[9] = keySchedule[i+9];
        byte[10] = keySchedule[i+10];
        byte[11] = keySchedule[i+11];
        byte[12] = keySchedule[i+12];
        byte[13] = keySchedule[i+13];
        byte[14] = keySchedule[i+14];
        byte[15] = keySchedule[i+15];
        printf("#%d ", i);
        binaryToHex(byte, 16);
    }
}