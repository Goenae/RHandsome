//
//
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "lib/aes.h"

#include "encryption.h"

void bytesToHexString(uint8_t *bytes, size_t length, char *hexString) {
    for (size_t i = 0; i < length; ++i) {
        sprintf(hexString + i * 2, "%02X", bytes[i]);
    }
}

void hexStringToBytes(const char *hexString, uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        sscanf(hexString + i * 2, "%2hhX", &bytes[i]);
    }
}

void decryptFile(struct AES_ctx ctx, char file_path[256]){
    //@file_path accepts both absolute and relative path

    //Open encrypted file
    FILE *src_fp;
    src_fp = fopen(file_path, "rb");

    //Parse file's path
    char *file_name = strrchr(file_path, '/');
    if (file_name == NULL) {
        file_name = file_path;
    } else {
        file_name++;
    }

    //Recreate raw file
    char end_fpth[256];

    //Remove encrypted file extension
    strcpy(end_fpth, file_name);
    end_fpth[strlen(end_fpth)-4] = '\0';

    //Create file
    FILE *end_fp;
    end_fp = fopen(end_fpth, "ab");

    //Chunk creation
    const size_t buffer_size = 4096;
    unsigned char buffer[buffer_size];

    //Read file's bytes chunk by chunk until the end
    size_t bytes_read;
    while((bytes_read = fread(buffer, 1, buffer_size, src_fp)) > 0){
        //Decrypt current chunk
        AES_CBC_decrypt_buffer(&ctx, buffer, bytes_read);
        //Write current decrypted chunk in the new file
        fwrite(buffer, 1, bytes_read, end_fp);

        //Clear buffer
        memset(buffer, 0, buffer_size);
    }

    //Remove the encrypted file
    //remove(file_path);



    fclose(src_fp);
    fclose(end_fp);
}

void encryptFile(struct AES_ctx ctx, char file_path[256]){
    //@file_path accepts both absolute and relative path

    //Open raw file
    FILE *src_fp;
    src_fp = fopen(file_path, "rb");

    //Parse file's path
    char *file_name = strrchr(file_path, '/');
    if (file_name == NULL) {
        file_name = file_path;
    } else {
        file_name++;
    }

    //Create new (encrypted) file
    char end_fpth[256];
    sprintf(end_fpth, "%s.cha", file_name);

    FILE *end_fp;
    end_fp = fopen(end_fpth, "ab");

    //Chunk creation
    const size_t buffer_size = 4096;
    unsigned char buffer[buffer_size];


    //Read file's bytes chunk by chunk until the end
    size_t bytes_read;
    while((bytes_read = fread(buffer, 1, buffer_size, src_fp)) > 0){
        //Add padding if the block isn't full
        /*if (bytes_read < buffer_size) {
            memset(buffer + bytes_read, 0, buffer_size - bytes_read);
        }*/
        //Encrypt current chunk
        //AES_CBC_encrypt_buffer(&ctx, buffer, buffer_size);
        //AES_CBC_decrypt_buffer(&ctx, buffer, buffer_size);
        AES_CTR_xcrypt_buffer(&ctx, buffer, buffer_size);
        AES_CTR_xcrypt_buffer(&ctx, buffer, buffer_size);

        printf("\n%zu", bytes_read);
        //Write current encrypted chunk in the new file
        fwrite(buffer, 1, bytes_read, end_fp);

        //Clear buffer
        memset(buffer, 0, buffer_size);
    }

    //Remove the raw file
    //remove(file_path);



    fclose(src_fp);
    fclose(end_fp);
}

void generateRandomBytes(uint8_t *array, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        array[i] = (uint8_t)rand();
    }
}
