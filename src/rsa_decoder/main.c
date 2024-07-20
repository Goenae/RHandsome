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

#define DEBUG 0

int main(int argc, char ** argv) {

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    struct private_key_class priv_key = { NULL };
    
    char* iv = argv[1];
    load_private_key("private_key.pem", &priv_key);
    unsigned char *decrypted_key = rsa_decrypt(iv, &priv_key);
    if(DEBUG){
    printf("%s", debug_bytes(decrypted_key, 16));

    // unsigned char *decrypted_iv = rsa_decrypt(encrypted_iv, &priv_key);
    // printf("\nIV déchiffré (hex) : %s\n\n", debug_bytes(decrypted_iv, 16));
    }
    

    free_private_key(&priv_key);

}
