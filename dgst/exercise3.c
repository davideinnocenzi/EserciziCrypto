#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main (int argc, char**argv){


    FILE *fp;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if(argc != 3){
        fprintf(stderr, "Error, invalid number of arguments\n");
        exit(1);
    }
    if (argv[1] == NULL){
        fprintf(stderr, "Error opening file 1\n");
        exit(1);
    }
    if (argv[2] == NULL){
        fprintf(stderr, "Error opening file 2\n");
        exit(1);
    }    
    if ((fp = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "File 1 open error\n");
        exit(1);
    }

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    const EVP_MD* algo = EVP_get_digestbyname(argv[2]);
    
    if(algo == NULL){
        handle_errors();
    }
    if(!EVP_DigestInit(md, algo))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXBUF];
    
    while((n_read = fread(buffer, sizeof(char), MAXBUF, fp)) > 0){
    // Returns 1 for success and 0 for failure.
        if(!EVP_DigestUpdate(md, buffer, n_read))
            handle_errors();
    }

    unsigned char md_value[EVP_MD_size(algo)];
    unsigned int md_len;

    if(!EVP_DigestFinal_ex(md, md_value, &md_len))
        handle_errors();
    
    EVP_MD_CTX_free(md);
    fclose(fp);
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    printf("The digest %s is: ", argv[2]);
    for(int i = 0; i < md_len; i++)
		printf("%02x", md_value[i]);
    printf("\n");

    return 0;
}