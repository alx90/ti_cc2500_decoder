#include <iostream>
#include <stdint.h>
#include <string> 
#include <stdio.h>
#include <cstring>
#include "main.hpp"

/**************************************************************************************************************
* DEFINES
*/
// NUMBER_OF_BYTES_AFTER_DECODING should be given the length of the payload + CRC (CRC is optional)
#define NUMBER_OF_BYTES_AFTER_DECODING 6
#define NUMBER_OF_BYTES_BEFORE_DECODING (4 * ((NUMBER_OF_BYTES_AFTER_DECODING / 2) + 1)) // 108
#define WHITENING_ON 0 // 0 whiteing disabled, 1 whitening enabled

/**************************************************************************************************************
* GLOBAL VARIABLES
*/
// The payload + CRC are 31 bytes. This way the complete packet to be received will fit in the RXFIFO
unsigned char rxBuffer[4]; // Buffer used to hold data read from the RXFIFO (4 bytes are read at a time)
unsigned char rxPacket[NUMBER_OF_BYTES_AFTER_DECODING]; // Data + CRC after being interleaved and decoded

const uint8_t INPUT_BUF[NUMBER_OF_BYTES_BEFORE_DECODING] = // 108 bytes
{
    // 0x4c,0xf0,0x30,0x10,0xc8,0x7c,0xc3,0x23,0x40,0x34,0x7c,0xe3 // -> 01 02 03 04 05 (no whitening)

    0xC8,0x3C,0x00,0x20,0x84,0xCF,0x33,0x31,0xA2,0xFC,0x40,0x4A,0x44,0x30,0x47,0xEF // ->  Input+CRC : 03 01 02 03 30 3A 

    // 0x25,0xB0,0x5B,0xBB,
    // 0x70,0x04,0x6C,0x79,
    // 0x8F,0xB6,0x5F,0x24,
    // 0x68,0xBC,0xB9,0xD0,
    // 0x23,0x29,0xF8,0x9A,
    // 0x91,0xFE,0xC3,0x6E,
    // 0xF3,0x81,0xAA,0x4F,
    // 0x36,0xCA,0xF9,0xE3,
    // 0x6E,0x95,0x0A,0x81,
    // 0x4F,0xE4,0x2D,0x68,
    // 0x7C,0x46,0x0D,0xD6,
    // 0x0B,0x83,0x1C,0xFF,
    // 0xB4,0xD5,0x09,0x6B,
    // 0xD6,0x05,0x67,0xD4,
    // 0xA5,0x8B,0x80,0xF6,
    // 0x6D,0x94,0xA0,0x27,
    // 0xD7,0x4A,0xA5,0xDD,
    // 0xDE,0xD9,0x04,0xC4,
    // 0x51,0xF5,0xC8,0x53,
    // 0x80,0xFE,0x35,0xBA,
    // 0x4D,0xDC,0xB8,0xE8,
    // 0x81,0x46,0x22,0xFB,
    // 0x8F,0x98,0x73,0xDE,
    // 0x10,0x9F,0xC4,0xF7,
    // 0x15,0xD8,0x33,0xF4,
    // 0xEF,0x0E,0x7E,0xF1,
    // 0xBB,0xCC,0xB8,0x12

    //  0x4E,0x35,0xD0,0xEB,
    //  0x7A,0x3F,0x67,0x6D,
    //  0x88,0xB6,0x63,0x10,
    //  0x64,0xB8,0xB5,0xE0,
    //  0x27,0x25,0xC8,0xAA,
    //  0x96,0xFC,0xFD,0x55,
    //  0xF3,0x81,0xAA,0x4F,
    //  0x36,0xCA,0xF9,0xE3,
    //  0x6E,0x95,0x0A,0x81,
    //  0x4F,0xE4,0x2D,0x68,
    //  0x7C,0x46,0x0D,0xD6,
    //  0x0B,0x83,0x1C,0xFF,
    //  0xB4,0xD5,0x09,0x6B,
    //  0xD6,0x05,0x67,0xD4,
    //  0x95,0x7F,0x7C,0x96,
    //  0x9D,0x64,0xF0,0xD7,
    //  0xD7,0x4A,0xA5,0xDD,
    //  0xE1,0xC9,0x3C,0x0C,
    //  0x71,0x05,0xC8,0xD3,
    //  0x84,0xF0,0x07,0x85,
    //  0x4D,0xDC,0xB8,0xE8,
    //  0x81,0x46,0x22,0xFB,
    //  0x8F,0x98,0x73,0xDE,
    //  0x10,0x9F,0xC4,0xF7,
    //  0x15,0xD8,0x33,0xF4,
    //  0xFF,0xD4,0xD4,0x32,
    //  0xBB,0xCF,0xBB,0x13,
    //  0xEB,0xDD,0xDD,0xEC
};

uint16_t calc_lfsr_ti(uint16_t prev_lfsr) 
{
    uint16_t result = ( (prev_lfsr&0x01) ^ ((prev_lfsr&0x20)>>5) )<<8  | (prev_lfsr>>1); // lfsr calculation TI-DN509
    return result;
};

uint16_t calc_lfsr_mavlink(uint16_t prev_lfsr) 
{
    uint16_t result = ((prev_lfsr<<1)&0x1fe) | (((prev_lfsr&8)>>3) ^((prev_lfsr&0x100)>>8)); // lfsr calculation mavlink
    return result;
};

void print_byte_array(const uint8_t* array, uint16_t array_len, std::string label) 
{
    std::cout << label << ": ";
    for (uint16_t i=0; i<array_len; i++) {
        printf("%02X ",array[i]);
    }
    std::cout << std::endl << std::endl;
};

uint8_t byte_swap(uint8_t b) {
    b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
    b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
    b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
    return b;
};

int main()
{
    // INPUT BYTE ARRAY
    print_byte_array(INPUT_BUF,NUMBER_OF_BYTES_BEFORE_DECODING,"INPUT_BUF");

    // DEWHITENING
    uint16_t lfsr = 0x1ff; // starting lfsr value
    uint8_t dewhitened_buf[NUMBER_OF_BYTES_BEFORE_DECODING];
    uint8_t dewhitened_buf_len=0;
    // MAVLINK decoding straight input
    int i=0;
    for (i=0; i<sizeof(INPUT_BUF); i++) {
        for (int j=0;j<8;j++) {
             lfsr = calc_lfsr_mavlink(lfsr);
            //lfsr = calc_lfsr_ti(lfsr);
        }
        if (WHITENING_ON)
            dewhitened_buf[i] = ~INPUT_BUF[i]^lfsr;
        else
            dewhitened_buf[i] = INPUT_BUF[i];
    }
    dewhitened_buf_len = i;
    print_byte_array(dewhitened_buf,dewhitened_buf_len,"DEWHITENED_BUF");

    // DECODE FEC
    unsigned char* input_buf_p = dewhitened_buf; // pointer to input buffer
    memset(rxPacket,0,sizeof(rxPacket)); // clear output buffer
    unsigned char* output_buf_p = rxPacket; // pointer to output buffer
    // Perform de-interleaving and decoding (both done in the same function)
    fecDecode(NULL, NULL, 0); // The function needs to be called with a NULL pointer for initialization before every packet to decode
    unsigned short nBytes = NUMBER_OF_BYTES_AFTER_DECODING;
    while (nBytes > 0) {
        // read input array 4 bytes at a time
        memcpy(rxBuffer,input_buf_p,4); // dest, source, num_of_bytes
        input_buf_p += 4;
        // decode 4 input bytes
        unsigned short nBytesOut;
        nBytesOut = fecDecode(output_buf_p, rxBuffer, nBytes);
        // printf("nBytes=%d rxBuffer=%02X:%02X:%02X:%02X \n", nBytes, rxBuffer[0], rxBuffer[1], rxBuffer[2], rxBuffer[3]);
        // update output buf pointers
        nBytes -= nBytesOut;
        output_buf_p += nBytesOut;
    }
    print_byte_array(rxPacket,NUMBER_OF_BYTES_AFTER_DECODING,"DECODED_BUF");

    // Perform CRC check (Optional)
    {
        unsigned short i;
        nBytes = NUMBER_OF_BYTES_AFTER_DECODING;
        unsigned short checksum = 0xFFFF;
        // Init value for CRC calculation
        for (i = 0; i < nBytes; i++)
            checksum = calcCRC(rxPacket[i], checksum);
        if (!checksum) {
            std::cout << ("CRC OK!!!") << std::endl;
            // Do something to indicate that the CRC is OK
        } else {
            std::cout << ("CRC WRONG!!!") << std::endl;
        }
    }

    return 0;
}