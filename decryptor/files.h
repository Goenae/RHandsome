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

#endif //BASIC_C_RANSOMWARE_FILES_H
