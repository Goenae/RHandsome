
#include <stdio.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include <string.h>
#include "encryption.h"

#define RSA_KEY_SIZE 4096


void error_and_exit(const char* msg) {
    printf("%s\n", msg);
    char buf[256];
    int err = ERR_get_error();
    ERR_error_string_n(err, buf, sizeof(buf));
    printf("errno: %d, %s\n", err, buf);
    exit(EXIT_FAILURE);
}


void decryptFile(unsigned char key[32], unsigned char iv[16], unsigned char aad[], char file_path[]) {
    //@file_path accepts both absolute and relative path

    unsigned char tag[16];

    FILE *inputFile, *outputFile;
    unsigned char *encrypted_text;
    long fileSize;

    // Open the input file in binary mode for reading
    if ((inputFile = fopen(file_path, "rb")) == NULL) {
        perror("Error opening input file");
        exit(1);
    }


    //Recreate raw file
    char end_fpth[256];

    //Remove encrypted file extension
    strcpy(end_fpth, file_path);
    end_fpth[strlen(end_fpth)-4] = '\0';

    // Open the output file in binary mode for writing
    if ((outputFile = fopen(end_fpth, "wb")) == NULL) {
        perror("Error opening output file");
        fclose(inputFile);
        exit(1);
    }

    // Find the size of the input file
    fseek(inputFile, 0, SEEK_END);
    fileSize = ftell(inputFile);
    fseek(inputFile, 0, SEEK_SET);

    // Allocate a buffer to store the entire content
    encrypted_text = (unsigned char*)malloc(fileSize);
    if (encrypted_text == NULL) {
        perror("Error allocating memory");
        fclose(inputFile);
        fclose(outputFile);
        exit(1);
    }

    // Read the entire content into the buffer
    if (fread(encrypted_text, 1, fileSize, inputFile) != fileSize) {
        perror("Error reading file");
        free(encrypted_text);
        fclose(inputFile);
        fclose(outputFile);
        exit(1);
    }

    int buffer_size = fileSize + strlen(aad);
    unsigned char *decrypted_text = malloc(buffer_size);

    decrypt(encrypted_text, fileSize, aad, strlen(aad), tag, key, iv, decrypted_text);

    // Write the entire content from the buffer to the output file
    if (fwrite(decrypted_text, 1, fileSize, outputFile) != fileSize) {
        perror("Error writing file");
        free(encrypted_text);
        fclose(inputFile);
        fclose(outputFile);

        free(decrypted_text);
        exit(1);
    }

    // Remove the encrypted file
    remove(file_path);

    // Close the files and free the buffer
    fclose(inputFile);
    fclose(outputFile);

    free(decrypted_text);
    free(encrypted_text);

}


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
            int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(aad && aad_len > 0)
    {
        if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(ciphertext)
    {
        if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();

        plaintext_len = len;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}
