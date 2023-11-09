//
//
//

#ifndef BASIC_C_RANSOMWARE_ENCRYPTION_H
#define BASIC_C_RANSOMWARE_ENCRYPTION_H

void hexStringToBytes(const char *hexString, uint8_t *bytes, size_t length);
void bytesToHexString(uint8_t *bytes, size_t length, char *hexString);
void decryptFile(struct AES_ctx ctx, char file_path[256]);
void encryptFile(struct AES_ctx ctx, char file_path[256]);
void generateRandomBytes(uint8_t *array, size_t length);

#endif //BASIC_C_RANSOMWARE_ENCRYPTION_H
