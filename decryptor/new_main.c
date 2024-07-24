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

char* debug_bytes(const unsigned char* byte_sequence, size_t sequence_size){
    char* lisible = (char*)malloc(sequence_size * 2 + 1);
    if (lisible == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }
    size_t j = 0;
    for (size_t i = 0; i < sequence_size; ++i) {
        j += sprintf(&lisible[j], "%02x", byte_sequence[i]);
    }

    return lisible;
}

unsigned char* hex_to_bytes(const char* hex_string, size_t* output_size) {
    size_t length = strlen(hex_string);
    if (length % 2 != 0) {
        fprintf(stderr, "Invalid hex string length.\n");
        exit(EXIT_FAILURE);
    }

    *output_size = length / 2;
    unsigned char* byte_array = (unsigned char*)malloc(*output_size);
    if (byte_array == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < *output_size; ++i) {
        sscanf(&hex_string[i * 2], "%2hhx", &byte_array[i]);
    }

    return byte_array;
}

char* get_user_path() {
    const char *user;
    char *path;

    #ifdef _WIN32
    user = getenv("USERNAME");
    size_t size = snprintf(NULL, 0, "C:\\Users\\%s", user) + 1;
    path = (char *)malloc(size);
    snprintf(path, size, "C:\\Users\\%s", user);
    #else
    user = getenv("USER");
    size_t size = snprintf(NULL, 0, "/home/%s", user) + 1;
    path = (char *)malloc(size);
    snprintf(path, size, "/home/%s", user);
    printf("%s", path);
    #endif

    return path;
}

void decrypt_files(unsigned char *key, unsigned char *iv, unsigned char *aad){
    char *path = get_user_path();
    PathList pathList;
    initPathList(&pathList);
    listFiles(path, &pathList);
    free(path);

    const char *ignoreDirs[] = {
        "Windows\\", "Program Files\\", "Programmes\\", "Programmes (x86)\\",
        "Program Files (x86)\\", "ProgramData\\", "$Recycle.Bin\\", "Corbeille\\", "AppData\\"
    };
    size_t num_ignoreDirs = sizeof(ignoreDirs) / sizeof(ignoreDirs[0]);

    for (size_t i = 0; i < pathList.count; ++i) {
        if (should_ignore_file(pathList.paths[i], ignoreDirs, num_ignoreDirs)) {
            continue;
        }

        char *extension = strrchr(pathList.paths[i], '.');
        if (extension != NULL && strcmp(extension, ".cha") == 0) {
            char encrypted_path[1024];
            snprintf(encrypted_path, sizeof(encrypted_path), "%s", pathList.paths[i]);
            decryptFile(key, iv, aad, encrypted_path);
            #ifdef _WIN32
            if (remove(encrypted_path) == 0) {
                printf("Decrypted file deleted successfully: %s\n", encrypted_path);
            } else {
                printf("Error deleting decrypted file: %s\n", encrypted_path);
            }
            #endif
        }
    }

    freePathList(&pathList);
}

int should_ignore_file(const char *path, const char *ignoreDirs[], size_t num_ignoreDirs) {
    for (size_t j = 0; j < num_ignoreDirs; ++j) {
        if (strstr(path, ignoreDirs[j]) != NULL) {
            return 1;
        }
    }
    return 0;
}

int main(){
    
    unsigned char* aes_key;
    unsigned char* iv;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    static const unsigned char aad[] = "Cyan";

    char* aes_string = "9ae33520fa98a9971486c959a19c7360010b62000f8e89313a40d698136f3002";
    char* iv_string = "19adcd15d50e56c2bfafedd721e6eff8"; 

    size_t aes_array_size = 32;
    size_t iv_array_size = 16;

    unsigned char* iv_byte_array = hex_to_bytes(iv_string, &iv_array_size);
    unsigned char* aes_byte_array = hex_to_bytes(aes_string, &aes_array_size);

    for (size_t i = 0; i < iv_array_size; ++i) {
        printf("%02x", iv_byte_array[i]);
    }
    printf("\n");

    for (size_t i = 0; i < aes_array_size; ++i) {
        printf("%02x", aes_byte_array[i]);
    }
    printf("\n");

    decrypt_files(aes_byte_array, iv_byte_array, aad);
    
    free(aes_byte_array);
    free(iv_byte_array);

    // debug_bytes(aes_key, 32);
    // debug_bytes(iv, 16);

    // free(aes_key);
    // free(iv);
    // decrypt_files();
    return 0;
}


