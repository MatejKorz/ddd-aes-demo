/*
    MIT license
    SPDX-License-Identifier: MIT
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>

#include "ddd-aes-ref-readability.h"

#define BLOCK_SIZE 512
#define BLOCK_COUNT 16

typedef enum
{
    MODE_NONE = 0,
    MODE_ENCRYPT = 1,
    MODE_DECRYPT = 2
} Mode;

int main(int argc, char* argv[])
{
    Mode mode = MODE_NONE;

    if (argc < 2) {
        printf("Usage: %s -e|-d\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-e") == 0) {
        mode = MODE_ENCRYPT;
    } else if (strcmp(argv[1], "-d") == 0) {
        mode = MODE_DECRYPT;
    } else {
        printf("Unknown option: %s\n", argv[1]);
        return 1;
    }

    uint8_t key_k[KEYSIZE_BYTES] = { 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                                     0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0 };
    uint8_t key_l[KEYSIZE_BYTES] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                     0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    uint8_t tweak[TWEAKSIZE_BYTES] = { 0 };
    uint8_t input_buff[BLOCK_SIZE] = { 0 };
    uint8_t output_buff[BLOCK_SIZE] = { 0 };

    int fd = open("input.bin", O_RDWR);
    if (fd < 0) {
        perror("open input file");
        return 1;
    }

    for (uint64_t iv = 0; iv < BLOCK_COUNT; iv++) {
        memset(tweak, 0, TWEAKSIZE_BYTES);
        uint64_t iv_le = htole64(iv);
        memcpy(tweak, &iv_le, sizeof(iv_le));

        off_t offset = (off_t)(iv * BLOCK_SIZE);
        ssize_t rbytes = pread(fd, input_buff, BLOCK_SIZE, offset);
        if (rbytes < 0) {
            perror("pread");
            return 1;
        }
        if (rbytes == 0) {
            break;
        }

        int status;
        switch (mode) {
            case MODE_ENCRYPT:
                status =
                  ddd_aes_ref_read_encrypt(output_buff, input_buff, BLOCK_SIZE, key_k, key_l, tweak, TWEAKSIZE_BYTES);
                break;
            case MODE_DECRYPT:
                status =
                  ddd_aes_ref_read_decrypt(output_buff, input_buff, BLOCK_SIZE, key_k, key_l, tweak, TWEAKSIZE_BYTES);
                break;
            default:
                status = -1;
        }

        if (status < 0) {
            fprintf(stderr, "ERROR: ddd_aes_ref_read failed, status: %d\n", status);
            return 1;
        }

        ssize_t wbytes = pwrite(fd, output_buff, (size_t)rbytes, offset);
        if (wbytes != rbytes) {
            perror("pwrite");
            return 1;
        }
    }

    return 0;
}
