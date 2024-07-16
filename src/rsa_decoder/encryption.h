struct public_key_class {
    RSA *rsa;
};

struct private_key_class {
    RSA *rsa;
};

int load_private_key(const char *priv_key_string, struct private_key_class *priv_key);
void free_private_key(struct private_key_class *priv_key);
unsigned char *rsa_decrypt(const char *encrypted_hex, struct private_key_class *priv_key);