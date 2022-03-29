#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define MAXBUF 1024

void handle_errors();

int main(int argc, const char *argv[]){
    FILE *fp;
    unsigned char *key;

    if(argc != 3){
        fprintf(stderr, "Error, invalid number of arguments\n");
        exit(1);
    }
    if (argv[1] == NULL){
        fprintf(stderr, "Enter a valid file\n");
        exit(1);
    }
    if (argv[2] == NULL){
        fprintf(stderr, "Enter a valid key\n");
        exit(1);
    }
    if ((fp = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "File open error\n");
        exit(1);
    }

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    key = (unsigned char *) malloc(strlen(argv[2])*sizeof(char));

    for (int i = 0; i < strlen(argv[2]); i++)
        key[i] = argv[2][i];
    

    EVP_MD_CTX *md = EVP_MD_CTX_new();

    if(!EVP_DigestInit(md, EVP_sha256()))
        handle_errors;

    if(!EVP_DigestUpdate(md, key, strlen(key)))
        handle_errors();
    
    int n_read;
    unsigned char buffer[MAXBUF];
    while((n_read = fread(buffer, sizeof(char), MAXBUF, fp)) > 0){
    // Returns 1 for success and 0 for failure.
        if(!EVP_DigestUpdate(md, buffer, n_read))
            handle_errors();

    }

    if(!EVP_DigestUpdate(md, key, strlen(key)))
        handle_errors();

    fclose(fp);
    
    unsigned char md_value[EVP_MD_size(EVP_sha256())];

    unsigned int md_len;

    //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
    if(!EVP_DigestFinal_ex(md, md_value, &md_len))
        handle_errors();

    // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
	EVP_MD_CTX_free(md);

    printf("The digest (sha256) is: ");
    for(int i = 0; i < md_len; i++)
		printf("%02x", md_value[i]);
    printf("\n");

    return 0;

}

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}
