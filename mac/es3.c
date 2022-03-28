#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

#define MAXBUF 1024

void handleErrors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main (int argc, char**argv){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(ctx);

    if(argc !=3 ){
        printf("ERROR in parameters");
        exit(1);
    }

    if(argv[1] == NULL){
        printf("ERROR in first parameter");
        exit(1);
    }

    if(argv[2] == NULL){
        printf("ERROR in second parameter");
        exit(1);
    }

    FILE* fp;

    if(((fp = fopen(argv[1],"r")) == NULL)){
        handleErrors();
    }
    
    if(!EVP_DigestInit(ctx,EVP_sha256())) {
        handleErrors();
    }

    if(!EVP_DigestUpdate(ctx,argv[1],strlen(argv[1]))){
        handleErrors();
    }

    size_t n;
    unsigned char buff[MAXBUF];

    while((n = fread(buff,1,MAXBUF,fp)) > 0 ){
        if(!EVP_DigestUpdate(ctx,buff,MAXBUF)) {
            handleErrors();
        }
    }

    if(!EVP_DigestUpdate(ctx,argv[1],strlen(argv[1]))){
        handleErrors();
    }


    unsigned char md[EVP_MD_size(EVP_sha256())];
    int md_len;

    if(!EVP_DigestFinal(ctx,md,&md_len)){
        handleErrors();
    }

    for(int i = 0; i < md_len; i++)
	     printf("%02x", md[i]);
    printf("\n");

    EVP_MD_CTX_free(ctx);
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
    return 0;
}