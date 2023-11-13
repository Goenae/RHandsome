gcc main.c files.c encryption.c lib/rsa.c lib/rsa.h lib/aes.c lib/aes.h -lcurl -o encrypt
gcc decryptor.c files.c encryption.c lib/rsa.c lib/rsa.h lib/aes.c lib/aes.h -lcurl -o decrypt
#./program
