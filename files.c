#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <curl/curl.h>

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#define PATH_SEPARATOR '\\'
#define SLEEP(seconds) Sleep((seconds) * 1000)
#else
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#define PATH_SEPARATOR '/'
#define SLEEP(seconds) sleep(seconds)
#endif


#include "files.h"

void listFiles(const char *path, PathList *pathList);
void initPathList(PathList *pathList);
void addToPathList(PathList *pathList, const char *path);
void freePathList(PathList *pathList);


// Function to list files for both Linux and Windows
void listFiles(const char *path, PathList *pathList) {
    
#ifdef _WIN32
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;

    char dirSpec[MAX_PATH];
    snprintf(dirSpec, sizeof(dirSpec), "%s\\*", path);

    hFind = FindFirstFile(dirSpec, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    } 

    do {
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (strcmp(findFileData.cFileName, ".") != 0 && strcmp(findFileData.cFileName, "..") != 0) {
                char subPath[MAX_PATH];
                snprintf(subPath, sizeof(subPath), "%s\\%s", path, findFileData.cFileName);
                listFiles(subPath, pathList);
            }
        } else {
            char filePath[MAX_PATH];
            snprintf(filePath, sizeof(filePath), "%s\\%s", path, findFileData.cFileName);
            addToPathList(pathList, filePath);
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);

#else
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (dp == NULL) {
        return;
    }

    while ((entry = readdir(dp)) != NULL) {
        if (entry->d_type == DT_REG) {
            char filePath[1024];
            snprintf(filePath, sizeof(filePath), "%s/%s", path, entry->d_name);
            addToPathList(pathList, filePath);
        } else if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                char subPath[1024];
                snprintf(subPath, sizeof(subPath), "%s/%s", path, entry->d_name);
                listFiles(subPath, pathList);
            }
        }
    }

    closedir(dp);
#endif
}

void initPathList(PathList *pathList) {
    pathList->paths = NULL;
    pathList->count = 0;
    pathList->capacity = 0;
}

void addToPathList(PathList *pathList, const char *path) {
    if (pathList->count >= pathList->capacity) {
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

