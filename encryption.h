//
//
//

#ifndef BASIC_C_RANSOMWARE_ENCRYPTION_H
#define BASIC_C_RANSOMWARE_ENCRYPTION_H

void decryptFile(struct AES_ctx ctx, char file_path[256]);
void encryptFile(struct AES_ctx ctx, char file_path[256]);
void generateRandomKey(uint8_t *key, size_t key_length);
void generateRandomIv(uint8_t *iv, size_t iv_length);

#endif //BASIC_C_RANSOMWARE_ENCRYPTION_H
