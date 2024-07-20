#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>


#include "encryption.h"


char* debug_bytes(const unsigned char* byte_sequence, size_t sequence_size);



int main(int argc, char ** argv) {

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    struct private_key_class priv_key = { NULL };
    
    char* iv = argv[1];
    load_private_key("private_key.pem", &priv_key);
    unsigned char *decrypted_key = rsa_decrypt(iv, &priv_key);
    printf("%s", debug_bytes(decrypted_key, 32));

    // unsigned char *decrypted_iv = rsa_decrypt(encrypted_iv, &priv_key);
    // printf("\nIV déchiffré (hex) : %s\n\n", debug_bytes(decrypted_iv, 16));

    free_private_key(&priv_key);

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


void free_private_key(struct private_key_class *priv_key) {
    if (priv_key->rsa) {
        RSA_free(priv_key->rsa);
        priv_key->rsa = NULL;
    }
}


int load_private_key(const char *priv_key_file, struct private_key_class *priv_key) {
    FILE *fp = fopen(priv_key_file, "rb");
    if (!fp) {
        perror("Erreur lors de l'ouverture du fichier de clé privée");
        return -1;
    }

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!rsa) {
        fprintf(stderr, "Erreur lors de la lecture de la clé privée PEM\n");
        return -1;
    }

    priv_key->rsa = rsa;

    return 0;
}

unsigned char *rsa_decrypt(const char *encrypted_hex, struct private_key_class *priv_key) {

    size_t encrypted_len = strlen(encrypted_hex) / 2;
    unsigned char *encrypted_data = (unsigned char *)malloc(encrypted_len);
    if (!encrypted_data) {
        perror("Erreur d'allocation de mémoire");
        return NULL;
    }

    for (size_t i = 0; i < encrypted_len; ++i) {
        sscanf(encrypted_hex + 2 * i, "%2hhx", &encrypted_data[i]);
    }

    unsigned char *decrypted_data = (unsigned char *)malloc(RSA_size(priv_key->rsa));
    if (!decrypted_data) {
        perror("Erreur d'allocation de mémoire");
        free(encrypted_data);
        return NULL;
    }

    int decrypted_length = RSA_private_decrypt(RSA_size(priv_key->rsa), encrypted_data, decrypted_data, priv_key->rsa, RSA_PKCS1_OAEP_PADDING);
    free(encrypted_data);

    if (decrypted_length == -1) {
        fprintf(stderr, "Erreur lors du déchiffrement RSA.\n");
        free(decrypted_data);
        return NULL;
    }

    decrypted_data[decrypted_length] = '\0'; 

    return decrypted_data;
}