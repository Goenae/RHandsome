#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <string.h>

void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
            int aad_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext, unsigned char *tag);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
            int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext);

#define BUFFER_SIZE 4096
void encrypt_file(unsigned char key[32], unsigned char iv[16], unsigned char aad[]){
    unsigned char tag[16];

    FILE *inputFile, *outputFile;
    unsigned char *plaintext;
    long fileSize;

    // Open the input file in binary mode for reading
    if ((inputFile = fopen("a.txt", "rb")) == NULL) {
        perror("Error opening input file");
        return 1;
    }

    // Open the output file in binary mode for writing
    if ((outputFile = fopen("b.txt", "wb")) == NULL) {
        perror("Error opening output file");
        fclose(inputFile);
        return 1;
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
        return 1;
    }

    // Read the entire content into the buffer
    if (fread(plaintext, 1, fileSize, inputFile) != fileSize) {
        perror("Error reading file");
        free(plaintext);
        fclose(inputFile);
        fclose(outputFile);
        return 1;
    }

    int buffer_size = sizeof(plaintext) + sizeof(aad);
    unsigned char ciphertext[buffer_size];
    unsigned char decryptedtext[buffer_size];
    int decryptedtext_len = 0, ciphertext_len = 0;

    printf("%s\n", plaintext);
    ciphertext_len = encrypt(plaintext, strlen(plaintext), aad, strlen(aad), key, iv, ciphertext, tag);

    decryptedtext_len = decrypt(ciphertext, ciphertext_len, aad, strlen(aad), tag, key, iv, decryptedtext);


    // Write the entire content from the buffer to the output file
    if (fwrite(plaintext, 1, fileSize, outputFile) != fileSize) {
        perror("Error writing file");
        free(plaintext);
        fclose(inputFile);
        fclose(outputFile);
        return 1;
    }

    // Close the files and free the buffer
    fclose(inputFile);
    fclose(outputFile);
    free(plaintext);
}

int main(int arc, char *argv[])
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Set up the key and iv. Do I need to say to not hard code these in a real application? :-) */

    /* A 256 bit key */
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    /* A 128 bit IV */
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    unsigned char plaintext[] = "I'm losing it";

    /* Some additional data to be authenticated */
    static const unsigned char aad[] = "Cyan";


    int buffer_size = sizeof(plaintext) + sizeof(aad);
    unsigned char ciphertext[buffer_size];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[buffer_size];

    /* Buffer for the tag */
    unsigned char tag[16];

    int decryptedtext_len = 0, ciphertext_len = 0;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt(plaintext, strlen(plaintext), aad, strlen(aad), key, iv, ciphertext, tag);


    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, ciphertext, ciphertext_len);
    printf("Tag is:\n");
    BIO_dump_fp(stdout, tag, 14);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, aad, strlen(aad), tag, key, iv, decryptedtext);

    // Add a NULL terminator. We are expecting printable text
    decryptedtext[decryptedtext_len] = '\0';

    // Show the decrypted text
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);

    /* Remove error strings */
    ERR_free_strings();

    encrypt_file(key, iv, aad);

    return 0;
}

void handleErrors(void)
{
    unsigned long errCode;

    printf("An error occurred\n");
    while(errCode = ERR_get_error())
    {
        char *err = ERR_error_string(errCode, NULL);
        printf("%s\n", err);
    }
    abort();
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