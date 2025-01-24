#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static FILE *inputfile;
static FILE *outputfile;

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

static const unsigned char Rcon[11] ={0xff, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

//Depends on AES version (128bit = 4, 196bit = 6, 256bit = 8)
#define Nk 4
//Depends on AES version (128bit = 10, 196bit = 12, 256bit = 14)
#define Nr 10
//Is always 4
#define Nb 4 
static unsigned char keySchedule[Nb *(Nr + 1)*4];
int keyCont = 4; //Index to continue from in the keySchedule

void binaryToHex(unsigned char bytes[], int byte_size, char *hex);
void hexToBinary(char *hex, int hexKardinality, unsigned char *bytes);
void encrypt_block(unsigned char key[], unsigned char block[], int blockSize);
void shiftRows(unsigned char *block);
void mixColumns(unsigned char *block);
void keyExpansion(unsigned char key[], unsigned char keySchedule[]);


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
    short keySize = 4*Nk; // key is 16 bytes
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
    
    // // Create KeySchedule from key
    // keyExpansion(key, keySchedule);
    // unsigned char byte[8] = {0};
    // for (int i = 0; i < Nb*(Nr+1)*4; i += 16)
    // {
    //     byte[0] = (keySchedule[i] << 4) | (keySchedule[i+1]);
    //     byte[1] = (keySchedule[i+2] << 4) | (keySchedule[i+3]);
        
    //     byte[2] = (keySchedule[i+4] << 4) | (keySchedule[i+5]);
    //     byte[3] = (keySchedule[i+6] << 4) | (keySchedule[i+7]);
        
    //     byte[4] = (keySchedule[i+8] << 4) | (keySchedule[i+9]);
    //     byte[5] = (keySchedule[i+10] << 4) | (keySchedule[i+11]);
        
    //     byte[6] = (keySchedule[i+12] << 4) | (keySchedule[i+13]);
    //     byte[7] = (keySchedule[i+14] << 4) | (keySchedule[i+15]);

    //     char output[16 + 1];
    //     binaryToHex(byte, 8, output);
    //     printf("%d# %s\n",i, output);
    // }
    

    // // outputfile = fopen("output.ans", "w");
    // //Stream in 16 bytes at a time and encrypt/decrypt each block separatley
    // // while(feof(inputfile) == 0){
    // //     counter = 0;
    // //     while(counter < keySize){
    // //         c = fgetc(inputfile);
    // //         block[counter++] = c;
    // //     }
    // //     // encrypt/decrypt
    // //     encrypt_block(key, block, 16);
    // //     // block is now encrypted 
    //     // fwrite(block, sizeof(block), 1, outputfile);
    // // }
    
    // int keyLength = sizeof(key)/sizeof(key[0]);
    // char keyHex[keyLength*2 + 1];
    // __uint8_t back2Binary[keyLength];
    // binaryToHex(key, keyLength, keyHex);
    // hexToBinary(keyHex, keyLength*2, back2Binary);
    
    // printf("Key in Hex: \n%s\n",keyHex);

   

    fclose(inputfile);
    // fclose(outputfile);
    
    return 0;
}

void binaryToHex(unsigned char bytes[], int byte_size, char *hex){
    char hexabeth[] = "0123456789ABCDEF";
    unsigned char left, right;
    int bin_len = byte_size;
    for (int i = 0; i < bin_len; i++)
    {
        //0b01101010
        unsigned char c = bytes[i];

        //0b00000110
        left = c >> 4; 
        
        //0b00001010
        right = c & 0xf;

        // printf("#%d c:%x, left:%x, right:%x\n", i, c, left, right);
        hex[2*i] = hexabeth[left];
        hex[2*i+1] = hexabeth[right];
    }

    //NULL terminate the string or else
    hex[bin_len*2] = '\0';
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
    // for (size_t i = 1; i <= 16; i++)
    // {
    //     printf("%3d ", block[i-1]);
    //     if (i % 4 == 0)
    //     {
    //         printf("\n");
    //     }
        
    // }
    
    unsigned char temp[2];
    //1th row clear

    //2nd row
    temp[0] = block[4];
    size_t i;
    for (i = 4; i < 7; i++)
    {
        block[i] = block[i+1];
    }
    block[7] = temp[0];

    // 3rd row
    temp[0] = block[8];
    temp[1] = block[9];
    block[8] = block[10];
    block[9] = block[11];
    block[10] = temp[0];
    block[11] = temp[1];

    // 4th row
    temp[0] = block[15];
    for (i = 15; i > 12; i--)
    {
        block[i] = block[i-1];
    }
    block[12] = temp[0];
}


//Inspired from Wikipedia, one time check when 
//the irreduciable polynomial theorem needs to be used 
unsigned char xtime(unsigned char byte){
    return (((byte >> 7) & 1) * 0x1b);
}

unsigned char gfMulti(unsigned char byte, int term){
    if(term == 1){
        return byte;
    }
    //check if polynomial is over the limit
    //adjust with irreduciable polynomial theorem
    __uint8_t adjust = xtime(byte);
    __uint8_t shifted = (byte << 1) ^ adjust;
    if (term == 3)
    {
        return shifted ^ byte;
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
        block[i] = (gfMulti(copy_block[i], 0x02) ^ gfMulti(copy_block[i+4], 0x03)) ^ copy_block[i+8]^ copy_block[i+12];
        block[i+4] = copy_block[i] ^ gfMulti(copy_block[i+4], 0x02) ^ gfMulti(copy_block[i+8], 0x03) ^ copy_block[i+12];
        block[i+8] = copy_block[i] ^ copy_block[i+4] ^ (gfMulti(copy_block[i+8], 0x02) ^ gfMulti(copy_block[i+12], 0x03));
        block[i+12] = gfMulti(copy_block[i], 0x03) ^ gfMulti(copy_block[i+12], 0x02) ^ copy_block[i+4] ^ copy_block[i+8];
    }
    
}

void addRoundKey(unsigned char *block, int blockSize, unsigned char *key){
    unsigned char RoundKey[16];
    
    // Assign key to be i:th Round key
    for (int i = 0; i < 4*Nk; i++)
    {
        //keyCont is a global variable
        RoundKey[i] = keySchedule[keyCont];
        RoundKey[i+1] = keySchedule[keyCont+1];
        RoundKey[i+2] = keySchedule[keyCont+2];
        RoundKey[i+3] = keySchedule[keyCont+3];
        keyCont += 4;
    }

    //XOR State with i:th Roundkey
    for (int i = 0; i < 4; i++)
    {
        block[i] = block[i] ^ RoundKey[i];
        block[i + 4] = block[i + 4] ^ RoundKey[i + 1];
        block[i + 8] = block[i + 8] ^ RoundKey[i + 2];
        block[i + 12] = block[i + 12] ^ RoundKey[i + 3];
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
    int i = 0;

    while (i < Nk)
    {
        keySchedule[i] = key[4*i];
        keySchedule[i + 1] = key[4*i + 1];
        keySchedule[i + 2] = key[4*i + 2];
        keySchedule[i + 3] = key[4*i + 3]; 
        i++;
    }
    
    i = Nk;
    while (i < (Nb*(Nr+1))*4)
    {
        //load previous word, each word will be based on its 4th generation
        temp[0] = keySchedule[(i-4)];
        temp[1] = keySchedule[(i-3)];
        temp[2] = keySchedule[(i-2)];
        temp[3] = keySchedule[(i-1)];
        if(i % Nk == 0){
            RotWord(temp);
            subBytes(temp, 4);
            for (size_t i = 0; i < 4; i++)
            {
                temp[i] = temp[i] ^ Rcon[i/Nk];
            }   
        }
        //Only for 256bit AES
        else if ((Nk > 6) && (i % Nk == 4)){
            subBytes(temp, 4);
        }
        keySchedule[i] = keySchedule[i-Nk] ^ temp[0];
        keySchedule[i+1] = keySchedule[i+1-Nk] ^ temp[1];
        keySchedule[i+2] = keySchedule[i+2-Nk] ^ temp[2];
        keySchedule[i+3] = keySchedule[i+3-Nk] ^ temp[3];
        // printf("tempe = %x %x %x %x\n", keySchedule[i], keySchedule[i+1], keySchedule[i+2], keySchedule[i+3]);
        i += 4;
    }
}

void encrypt_block(unsigned char key[], unsigned char block[], int blockSize){
    int rounds = 10;
    unsigned char *state = block;

    //Use 0th Roundkey (given) on state
    for (int i = 0; i < blockSize; i++)
    {
        state[i] = state[i] ^ key[i];
    }
    
    //Start the rounds
    for (int i = 0; i < Nr-1; i++)
    {
        subBytes(state, blockSize);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, blockSize, key); //we updated the Key and apply the key here
    }

    //last round, no mix-columns
    subBytes(state, blockSize);
    shiftRows(state);
    addRoundKey(state, blockSize, key);

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