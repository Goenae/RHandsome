#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <string.h>

void handleErrors(void);
int encryptFile(const char *inputFile, const char *outputFile, unsigned char *aad, unsigned char *key, unsigned char *iv, unsigned char *tag);
int decryptFile(const char *inputFile, const char *outputFile, unsigned char *aad, unsigned char *key, unsigned char *iv, unsigned char *tag);

int main(int argc, char *argv[])
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Set up the key and iv. Do not hard code these in a real application. */
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    /* Some additional data to be authenticated */
    static const unsigned char aad[] = "Cyan";

    unsigned char tag[16];

    /* Encrypt a file */
    encryptFile("a.txt", "a.txt.cha", aad, key, iv, tag);

    /* Decrypt the file */
    decryptFile("a.txt.cha", "b.txt", aad, key, iv, tag);

    /* Remove error strings */
    ERR_free_strings();

    return 0;
}
/*
int encryptFile(const char *inputFile, const char *outputFile, unsigned char *aad, unsigned char *key, unsigned char *iv, unsigned char *tag)
{
    FILE *inFile = fopen(inputFile, "rb");

    fseek(inFile, 0, SEEK_END);
    size_t fileSize = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    unsigned char *plaintext = malloc(fileSize);

    size_t bytesRead = fread(plaintext, 1, fileSize, inFile);
    int buffer_size = bytesRead + 16;
    unsigned char ciphertext[buffer_size];
    fclose(inFile);


    FILE *outFile = fopen(outputFile, "wb");


    int ciphertext_len = encrypt(plaintext, sizeof(plaintext), aad, strlen(aad), key, iv, ciphertext, tag);
    printf("%s\n", ciphertext);
    printf("%d\n", ciphertext_len);
    printf("%s\n", plaintext);
    fwrite(ciphertext, 1, ciphertext_len, outFile);

    fclose(outFile);
    free(plaintext);

    return 0;
}
*/

int encryptFile(const char *inputFile, const char *outputFile, unsigned char *aad, unsigned char *key, unsigned char *iv, unsigned char *tag)
{
    FILE *inFile = fopen(inputFile, "rb");

    fseek(inFile, 0, SEEK_END);
    size_t fileSize = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    unsigned char *plaintext = malloc(fileSize);

    size_t bytesRead = fread(plaintext, 1, fileSize, inFile);
    fclose(inFile);

    int buffer_size = bytesRead + 16;
    unsigned char *ciphertext = malloc(buffer_size);

    FILE *outFile = fopen(outputFile, "wb");

    int ciphertext_len = encrypt(plaintext, bytesRead, aad, strlen(aad), key, iv, ciphertext, tag);
    if (ciphertext_len == -1) {
        perror("Error encrypting file");
        fclose(outFile);
        free(plaintext);
        free(ciphertext);
        return -1;
    }

    fwrite(ciphertext, 1, ciphertext_len, outFile);

    fclose(outFile);
    free(plaintext);
    free(ciphertext);

    return 0;
}

/*
int decryptFile(const char *inputFile, const char *outputFile, unsigned char *aad, unsigned char *key, unsigned char *iv, unsigned char *tag)
{
    FILE *inFile = fopen(inputFile, "rb");
    if (!inFile) {
        perror("Error opening input file");
        return -1;
    }

    fseek(inFile, 0, SEEK_END);
    size_t fileSize = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    unsigned char *ciphertext = malloc(fileSize);
    if (!ciphertext) {
        perror("Error allocating memory for ciphertext");
        fclose(inFile);
        return -1;
    }

    size_t bytesRead = fread(ciphertext, 1, fileSize, inFile);
    fclose(inFile);

    if (bytesRead != fileSize) {
        perror("Error reading input file");
        free(ciphertext);
        return -1;
    }

    FILE *outFile = fopen(outputFile, "wb");
    if (!outFile) {
        perror("Error opening output file");
        free(ciphertext);
        return -1;
    }

    int plaintext_len = decrypt(ciphertext, bytesRead, aad, strlen(aad), tag, key, iv, NULL);
    if (plaintext_len == -1) {
        perror("Error decrypting file");
        fclose(outFile);
        free(ciphertext);
        return -1;
    }

    fwrite(ciphertext, 1, plaintext_len, outFile);

    fclose(outFile);
    free(ciphertext);

    return 0;
}
*/

int decryptFile(const char *inputFile, const char *outputFile, unsigned char *aad, unsigned char *key, unsigned char *iv, unsigned char *tag)
{
    FILE *inFile = fopen(inputFile, "rb");
    if (!inFile) {
        perror("Error opening input file");
        return -1;
    }

    fseek(inFile, 0, SEEK_END);
    size_t fileSize = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    unsigned char *ciphertext = malloc(fileSize);
    if (!ciphertext) {
        perror("Error allocating memory for ciphertext");
        fclose(inFile);
        return -1;
    }

    size_t bytesRead = fread(ciphertext, 1, fileSize, inFile);
    fclose(inFile);

    if (bytesRead != fileSize) {
        perror("Error reading input file");
        free(ciphertext);
        return -1;
    }

    FILE *outFile = fopen(outputFile, "wb");
    if (!outFile) {
        perror("Error opening output file");
        free(ciphertext);
        return -1;
    }

    int plaintext_len = decrypt(ciphertext, bytesRead, aad, strlen(aad), tag, key, iv, NULL);
    if (plaintext_len == -1) {
        perror("Error decrypting file");
        fclose(outFile);
        free(ciphertext);
        return -1;
    }

    fwrite(ciphertext, 1, plaintext_len, outFile);

    fclose(outFile);
    free(ciphertext);

    return 0;
}


void handleErrors(void)
{
    unsigned long errCode;

    printf("An error occurred\n");
    while (errCode = ERR_get_error())
    {
        char *err = ERR_error_string(errCode, NULL);
        printf("%s\n", err);
    }
    //abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
            int aad_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    if (aad && aad_len > 0)
    {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    if (plaintext)
    {
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();

        ciphertext_len = len;
    }

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
/*
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
            int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    if (aad && aad_len > 0)
    {
        if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    if (ciphertext)
    {
        if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();

        plaintext_len = len;
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        return -1;
    }
}*/
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
            int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    if (aad && aad_len > 0)
    {
        if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    if (ciphertext)
    {
        if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();

        plaintext_len = len;
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    if (ret > 0)
    {
        plaintext_len += len;
    }
    else
    {
        handleErrors();
    }

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

