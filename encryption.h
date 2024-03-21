//
//
//

#ifndef BASIC_C_RANSOMWARE_ENCRYPTION_H
#define BASIC_C_RANSOMWARE_ENCRYPTION_H

void error_and_exit(const char* msg);
unsigned char* encrypt_RSA(const char *public_key_pem, unsigned char* in);
void encrypt_file(unsigned char key[32], unsigned char iv[16], unsigned char aad[], char file_path[]);
void decryptFile(unsigned char key[32], unsigned char iv[16], unsigned char aad[], char file_path[]);
void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
            int aad_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext, unsigned char *tag);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
            int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext);


#endif //BASIC_C_RANSOMWARE_ENCRYPTION_H
