/**
 *      @file    psk.h
 *      @version 5a72845 (tag: 4-0-1-open)
 *
 *      Example Pre-Shared Key header file with randomly generated data.
 */

typedef struct
{
    unsigned char id[16];
    unsigned char key[16];
} pskStruct_t;

#define PSK_HEADER_TABLE_COUNT (sizeof(PSK_HEADER_TABLE) / sizeof(pskStruct_t))

static const pskStruct_t PSK_HEADER_TABLE[] = {
    /*  This first id (the string "Client_identity", with null terminator)
        and key will negotiate with:
        openssl s_server -psk 33c841e5a8164812370b4757d6888630 ...
     */
    { { 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64,
        0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x00 },
        { 0x33, 0xc8, 0x41, 0xe5, 0xa8, 0x16, 0x48, 0x12, 0x37,
        0x0b, 0x47, 0x57, 0xd6, 0x88, 0x86, 0x30 } },
    /* The following ids and keys are randomly generated */
    { { 0x37, 0x30, 0x31, 0x35, 0x46, 0x33, 0x33, 0x35, 0x42,
        0x37, 0x43, 0x30, 0x33, 0x43, 0x38, 0x39 },
        { 0xac, 0xc5, 0xb5, 0x79, 0xe1, 0x00, 0xf6, 0xa9, 0x8f,
        0xb4, 0x8b, 0xf7, 0x55, 0xa9, 0x1f, 0x33 } },
    { { 0x32, 0x43, 0x38, 0x39, 0x38, 0x44, 0x36, 0x35, 0x36,
        0x32, 0x44, 0x34, 0x35, 0x41, 0x37, 0x30 },
        { 0x9d, 0x3f, 0x10, 0x1b, 0xfd, 0x5c, 0xe3, 0x18, 0xfa,
        0x66, 0x34, 0xad, 0x87, 0xa0, 0xe1, 0x40 } },
    { { 0x30, 0x43, 0x43, 0x39, 0x33, 0x33, 0x37, 0x30, 0x43,
        0x39, 0x42, 0x37, 0x39, 0x36, 0x37, 0x31 },
        { 0xa2, 0x7c, 0x3e, 0x53, 0x7c, 0x34, 0xb8, 0x52, 0x0b,
        0x21, 0x93, 0x29, 0x07, 0x59, 0x40, 0x29 } }
};

