#include <iostream>
#include <stdint.h>
#include <string> 
#include <stdio.h>
#include <cstring>
#include "main.hpp"

// CONFIG CONSTANTS
static const bool IS_INVERTED = true; // false->decode input buf as declared,  true->invert input buf before decoding
static const bool IS_WHITENED = true; // false->disable de-whitening, true->enable de-whitening
static const bool CHECK_CRC = false; // make sure crc is included in input_buf for correct check. false->do not check CRC, true->check CRC is correct
static const uint16_t NUMBER_OF_BYTES_AFTER_DECODING = 52; // payload+crc(optional), NOTE change this according to input_buf
static const uint16_t NUMBER_OF_BYTES_BEFORE_DECODING = (4 * ((NUMBER_OF_BYTES_AFTER_DECODING / 2) + 1)); // 108 input_buf len

// GLOBAL VARIABLES
unsigned char result_buf[NUMBER_OF_BYTES_AFTER_DECODING]; // Data + CRC after being interleaved and decoded
uint8_t input_buf[NUMBER_OF_BYTES_BEFORE_DECODING] = // 108 bytes
{
    // INPUT1 inverted=true,whitened=false,bytes_after_decoding=52 -> OUTPUT FD 1A 3A 00 AA 0B BB 0B B5 0B B6 0B B8 0B B8 0B B8 0B B8 0B B8 0B B8 0B B8 0B B8 0B 8C 0A BD FF FE 7F FF FF FF FF 7F 07 B3 96 00 01 50 00 00 45 76 A5 57 BD (payload+crc)
    // 0x41,0x0A,0x45,0x54,
    // 0xF5,0xF0,0xC8,0xC8,
    // 0xB5,0xFF,0x86,0x0C,
    // 0xBA,0xC0,0xBA,0x1A,
    // 0xB2,0xF4,0xB2,0x06,
    // 0xB2,0xF4,0xB2,0x06,
    // 0xB2,0xFC,0xBA,0x3A,
    // 0xB2,0xFC,0xBA,0x3A,
    // 0xB2,0xFC,0xBA,0x3A,
    // 0xB2,0xFC,0xBA,0x3A,
    // 0xB2,0xFC,0xBA,0x3A,
    // 0xB2,0xFC,0xBA,0x3A,
    // 0xB2,0xFC,0xBA,0x3A,
    // 0xB2,0xFC,0xBA,0x3A,
    // 0x7C,0xF7,0xA6,0x02,
    // 0x52,0x5B,0x65,0x6B,
    // 0x42,0xAA,0xEA,0xEA,
    // 0xAA,0xAA,0xAA,0xAA,
    // 0xAA,0xAA,0xAA,0xAB,
    // 0x6C,0x8C,0x69,0xCC,
    // 0xED,0x73,0xBA,0x94,
    // 0xFF,0xFF,0xF3,0xFF,
    // 0xFF,0xC7,0xCF,0xDB,
    // 0x3E,0x5E,0x1E,0x7F,
    // 0xAD,0x72,0xD3,0x09,
    // 0x47,0xB9,0xCF,0x9A,
    // 0xDD,0xE7,0xCC,0x09
    // // 0xC0,0x00,0x00,0x00,
    // // 0x00,0x00,0x00,0x03 

    // INPUT1 inverted=true,whitened=true,bytes_after_decoding=52 -> OUTPUT FD 1A 3A 00 AA 0B BB 0B B5 0B B6 0B B8 0B B8 0B B8 0B B8 0B B8 0B B8 0B B8 0B B8 0B 8C 0A BD FF FE 7F FF FF FF FF 7F 07 B3 96 00 01 50 00 00 45 76 A5 57 BD (payload+crc)
    0x9B,0x23,0xAF,0x7F,
    0x7A,0x37,0x6F,0x51,
    0x88,0xB6,0x63,0x10,
    0x60,0x80,0xB9,0xF0,
    0x27,0x25,0xC8,0xAA,
    0x91,0xCA,0xFF,0x4E,
    0xF3,0x81,0xAA,0x4F,
    0x36,0xCA,0xF9,0xE3,
    0x6E,0x95,0x0A,0x81,
    0x4F,0xE4,0x2D,0x68,
    0x7C,0x46,0x0D,0xD6,
    0x0B,0x83,0x1C,0xFF,
    0xB4,0xD5,0x09,0x6B,
    0xD6,0x05,0x67,0xD4,
    0x95,0x7F,0x7C,0x96,
    0xAA,0x59,0xD3,0xDB,
    0xEB,0x4A,0x85,0xFD,
    0xED,0xC5,0x38,0x00,
    0x41,0xC5,0x08,0x93,
    0x80,0xFE,0x35,0xBA,
    0x4D,0xDC,0xB8,0xE8,
    0x81,0x46,0x22,0xFB,
    0x8F,0x98,0x73,0xDE,
    0x10,0x9F,0xC4,0xF7,
    0x15,0xD8,0x33,0xF4,
    0x17,0x2F,0x41,0x19,
    0xBB,0xCF,0xBB,0x13
    // 0x80,0x00,0x00,0x00,
    // 0x00,0x00,0x00,0x03 

    // INPUT2 inverted=false,whitened=false,bytes_after_decoding=5 -> OUTPUT 01 02 03 04 05 (payload only)
    // 0x4c,0xf0,0x30,0x10,0xc8,0x7c,0xc3,0x23,0x40,0x34,0x7c,0xe3

    // INPUT3 inverted=false,whitened=false,bytes_after_decoding=6 -> OUTPUT 03 01 02 03 30 3A (payload+crc)
    // 0xC8,0x3C,0x00,0x20,0x84,0xCF,0x33,0x31,0xA2,0xFC,0x40,0x4A,0x44,0x30,0x47,0xEF
};





// UTILITY FUNCTIONS
uint16_t calc_lfsr_ti(uint16_t prev_lfsr) // lfsr calculation TI-DN509
{
    uint16_t result = ( (prev_lfsr&0x01) ^ ((prev_lfsr&0x20)>>5) )<<8  | (prev_lfsr>>1);
    return result;
};
uint16_t calc_lfsr_mavlink(uint16_t prev_lfsr) // lfsr calculation mavlink
{
    uint16_t result = ((prev_lfsr<<1)&0x1fe) | (((prev_lfsr&8)>>3) ^((prev_lfsr&0x100)>>8));
    return result;
};
uint8_t reverse_bits_in_byte(uint8_t byte) // reverse bit positions in byte (msb becomes lsb etc...)
{ 
    byte = (byte & 0xF0) >> 4 | (byte & 0x0F) << 4;
    byte = (byte & 0xCC) >> 2 | (byte & 0x33) << 2;
    byte = (byte & 0xAA) >> 1 | (byte & 0x55) << 1;
    return byte;
};
void invert_byte_array(uint8_t* array, uint16_t array_len) {
    for (int i=0; i<array_len; i++) {
        array[i] = ~array[i];
    }
};
void print_byte_array(const uint8_t* array, uint16_t array_len, std::string label)
{
    std::cout << label << ": ";
    for (uint16_t i=0; i<array_len; i++) {
        printf("%02X ",array[i]);
    }
    std::cout << std::endl << std::endl;
};





// MAIN
int main()
{
    // LOG INPUT BYTE ARRAY AS IS
    print_byte_array(input_buf,NUMBER_OF_BYTES_BEFORE_DECODING,"INPUT_BUF");

    if (IS_INVERTED) {
        invert_byte_array(input_buf,NUMBER_OF_BYTES_BEFORE_DECODING); // invert in-place
        print_byte_array(input_buf,NUMBER_OF_BYTES_BEFORE_DECODING,"INVERTED_BUF");
    }

    // DECODE FEC
    unsigned char* input_buf_p = input_buf; // pointer to input buffer
    memset(result_buf,0,sizeof(result_buf)); // clear output buffer
    unsigned char* output_buf_p = result_buf; // pointer to output buffer
    unsigned char tmp_buf[4]; // tmp_buf used to process input_buf 4 bytes at a time
    // Perform de-interleaving and decoding (both done in the same function)
    fecDecode(NULL, NULL, 0); // The function needs to be called with a NULL pointer for initialization before every packet to decode
    unsigned short nBytes = NUMBER_OF_BYTES_AFTER_DECODING;
    while (nBytes > 0) {
        // read input array 4 bytes at a time
        memcpy(tmp_buf,input_buf_p,4); // dest, source, num_of_bytes
        input_buf_p += 4;
        // decode 4 input bytes
        unsigned short nBytesOut;
        nBytesOut = fecDecode(output_buf_p, tmp_buf, nBytes);
        // printf("nBytes=%d tmp_buf=%02X:%02X:%02X:%02X \n", nBytes, tmp_buf[0], tmp_buf[1], tmp_buf[2], tmp_buf[3]);
        // update output buf pointers
        nBytes -= nBytesOut;
        output_buf_p += nBytesOut;
    }
    print_byte_array(result_buf,sizeof(result_buf),"FEC_DECODED_BUF");

    if (IS_WHITENED) {
        // DEWHITENING
        uint16_t lfsr = 0x1ff; // starting lfsr value
        // MAVLINK decoding straight input
        int i=0;
        for (i=0; i<sizeof(result_buf); i++) {
            result_buf[i] = result_buf[i]^lfsr;
            for (int j=0;j<8;j++) { // NOTE FOR AFTER ^, INCLUDING INITIAL lfsr IN DE-WHITENING SEQUENCE
                lfsr = calc_lfsr_ti(lfsr);
                //  lfsr = calc_lfsr_mavlink(lfsr);
            }
        }
        print_byte_array(result_buf,sizeof(result_buf),"DEWHITENED_BUF");
    }

    if (CHECK_CRC) {
        // OPTIONAL CRC CHECK
        unsigned short checksum = 0xFFFF; // Init value for CRC calculation
        for (uint16_t i = 0; i < sizeof(result_buf); i++)
            checksum = calcCRC(result_buf[i], checksum);
        if (!checksum) {
            std::cout << ("CRC OK!!!") << std::endl;
        } else {
            std::cout << ("CRC WRONG!!!") << std::endl;
        }
    }

    return 0;
}