#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#define MAXBUF 1024

void handle_errors();

int main(int argc, const char *argv[]){
    FILE *fp;
    FILE *fp2;
    FILE *concat;

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
    if ((fp2 = fopen(argv[2], "r")) == NULL){
        fprintf(stderr, "File 2 open error\n");
        exit(1);
    }
    if ((concat = fopen("concat.txt", "rw")) == NULL){
        fprintf(stderr, "File 2 open error\n");
        exit(1);
    }


    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    EVP_MD_CTX *md256 = EVP_MD_CTX_new();
    EVP_MD_CTX *md512 = EVP_MD_CTX_new();
    EVP_MD_CTX *md3 = EVP_MD_CTX_new();
    if(!EVP_DigestInit(md256, EVP_sha256()))
        handle_errors;
    if(!EVP_DigestInit(md512, EVP_sha512()))
        handle_errors;
    if(!EVP_DigestInit(md3, EVP_sha3_256()))
        handle_errors;
    
    int n_read;
    unsigned char buffer[MAXBUF];
    while((n_read = fread(buffer, sizeof(char), MAXBUF, fp)) > 0){
    // Returns 1 for success and 0 for failure.
        if(!EVP_DigestUpdate(md256, buffer, n_read))
            handle_errors();
        if(!EVP_DigestUpdate(md512, buffer, n_read))
            handle_errors();
        if(!EVP_DigestUpdate(md3, buffer, n_read))
            handle_errors();
    }

    while((n_read = fread(buffer, sizeof(char), MAXBUF, fp2)) > 0){
    // Returns 1 for success and 0 for failure.
        if(!EVP_DigestUpdate(md256, buffer, n_read))
            handle_errors();
        if(!EVP_DigestUpdate(md512, buffer, n_read))
            handle_errors();
        if(!EVP_DigestUpdate(md3, buffer, n_read))
            handle_errors();
    }

    unsigned char md256_value[EVP_MD_size(EVP_sha256())];
    unsigned char md512_value[EVP_MD_size(EVP_sha512())];
    unsigned char md3_value[EVP_MD_size(EVP_sha3_256())];
    unsigned int md256_len, md512_len, md3_len;

    //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
    if(!EVP_DigestFinal_ex(md256, md256_value, &md256_len))
        handle_errors();

    if(!EVP_DigestFinal_ex(md512, md512_value, &md512_len))
        handle_errors();
    
    if(!EVP_DigestFinal_ex(md3, md3_value, &md3_len))
        handle_errors();

    // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
	EVP_MD_CTX_free(md256);
    EVP_MD_CTX_free(md512);
    EVP_MD_CTX_free(md3);

    printf("The digest (sha256) is: ");
    for(int i = 0; i < md256_len; i++)
		printf("%02x", md256_value[i]);
    printf("\n");

    printf("The digest (sha512) is: ");
    for(int i = 0; i < md512_len; i++)
		printf("%02x", md512_value[i]);
    printf("\n");

    printf("The digest (sha3) is: ");
    for(int i = 0; i < md3_len; i++)
		printf("%02x", md3_value[i]);
    printf("\n");

    fclose(fp);
    fclose(fp2);
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}
