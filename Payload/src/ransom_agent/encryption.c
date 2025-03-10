
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

char* debug_bytes(const unsigned char* byte_sequence, size_t sequence_size){
    char* lisible = (char*)malloc(sequence_size * 2 + 1); 
    if (lisible == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }
    size_t j = 0;
    for (size_t i = 0; i < sequence_size; ++i) {
        j += sprintf(&lisible[j], "%02x", byte_sequence[i]);
    }
    return lisible;
}


void free_public_key(struct public_key_class *pub_key) {
    if (pub_key->rsa) {
        RSA_free(pub_key->rsa);
        pub_key->rsa = NULL;
    }
}


int load_public_key(const char *public_key, struct public_key_class *pub_key) {
    BIO *bio = BIO_new_mem_buf(public_key, -1);
    if (!bio) {
        fprintf(stderr, "Error creating BIO in memory\n");
        return -1;
    }

    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!rsa) {
        fprintf(stderr, "Error reading public key PEM\n");
        return -1;
    }

    pub_key->rsa = rsa;

    return 0;
}


char *rsa_encrypt(const char *iv_lisible, struct public_key_class *pub_key) {

    size_t hex_len = strlen(iv_lisible);
    if (hex_len % 2 != 0) {
        fprintf(stderr, "The hexa string length is not even.\n");
        return NULL;
    }

    size_t bin_len = hex_len / 2;
    unsigned char *binary_data = (unsigned char *)malloc(bin_len);
    if (!binary_data) {
        perror("Error allocating memory");
        return NULL;
    }


    for (size_t i = 0; i < bin_len; ++i) {
        sscanf(iv_lisible + 2 * i, "%2hhx", &binary_data[i]);
    }


    unsigned char *encrypted_data = (unsigned char *)malloc(RSA_size(pub_key->rsa));
    if (!encrypted_data) {
        perror("Error allocating memory");
        free(binary_data);
        return NULL;
    }

    int encrypted_length = RSA_public_encrypt(bin_len, binary_data, encrypted_data, pub_key->rsa, RSA_PKCS1_OAEP_PADDING);
    free(binary_data); 

    if (encrypted_length == -1) {
        fprintf(stderr, "Error during RSA encryption.\n");
        free(encrypted_data);
        return NULL;
    }


    char *encrypted_hex = (char *)malloc(2 * encrypted_length + 1);
    if (!encrypted_hex) {
        perror("Error allocating memory");
        free(encrypted_data);
        return NULL;
    }

    for (int i = 0; i < encrypted_length; ++i) {
        sprintf(&encrypted_hex[2*i], "%02x", encrypted_data[i]);
    }
    encrypted_hex[2 * encrypted_length] = '\0';

    free(encrypted_data); // Libérer la mémoire après utilisation des données chiffrées

    return encrypted_hex;
}


void encrypt_file(unsigned char key[32], unsigned char iv[16], unsigned char aad[], char file_path[]){
    //@file_path accepts both absolute and relative path

    unsigned char tag[16];

    FILE *inputFile, *outputFile;
    unsigned char *plaintext;
    long fileSize;

    // Open the input file in binary mode for reading
    if ((inputFile = fopen(file_path, "rb")) == NULL) {
        perror("Error opening input file");
        exit(1);
    }


    //Create new (encrypted) file
    char end_fpth[strlen(file_path+4)];
    sprintf(end_fpth, "%s.cha", file_path);

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
    plaintext = (unsigned char*)malloc(fileSize);
    if (plaintext == NULL) {
        perror("Error allocating memory");
        fclose(inputFile);
        fclose(outputFile);
        exit(1);
    }

    // Read the entire content into the buffer
    if (fread(plaintext, 1, fileSize, inputFile) != fileSize) {
        perror("Error reading file");
        free(plaintext);
        fclose(inputFile);
        fclose(outputFile);
        exit(1);
    }

    int buffer_size = fileSize + strlen(aad);
    unsigned char *ciphertext = malloc(buffer_size);

    encrypt(plaintext, fileSize, aad, strlen(aad), key, iv, ciphertext, tag);


    // Write the entire content from the buffer to the output file
    if (fwrite(ciphertext, 1, fileSize, outputFile) != fileSize) {
        perror("Error writing file");
        free(plaintext);
        fclose(inputFile);
        fclose(outputFile);

        free(ciphertext);
        exit(1);
    }

    // Remove the base file
    remove(file_path);

    // Close the files and free the buffer
    fclose(inputFile);
    fclose(outputFile);

    free(ciphertext);
    free(plaintext);
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

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
            int aad_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(aad && aad_len > 0)
    {
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(plaintext)
    {
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();

        ciphertext_len = len;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
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
