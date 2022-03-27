#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main (int argc, char**argv){
           
        unsigned char key[] = "alessandrolocons";
      
        if(argc != 2){
            fprintf(stderr,"Invalid parameters. Usage: %s filename\n",argv[0]);
            exit(1);
        }

        FILE *f_in;
        if((f_in = fopen(argv[1],"r")) == NULL) {
                fprintf(stderr,"Couldn't open the input file, try again\n");
                exit(1);
        }

        ERR_load_crypto_strings();
        /* Load all digest and cipher algorithms */
        OpenSSL_add_all_algorithms();

        EVP_MD_CTX  *hmac_ctx = EVP_MD_CTX_new();
        EVP_PKEY *hkey;
        hkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, 16);

        if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hkey))
            handle_errors();
        
        size_t n;
        unsigned char buffer[MAXBUF];
        while((n = fread(buffer,1,MAXBUF,f_in)) > 0){
        // Returns 1 for success and 0 for failure.
            if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n))
                handle_errors();
        }
        unsigned char hmac_value[EVP_MD_size(EVP_sha256())];
        size_t hmac_len;
        
        if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
            handle_errors();

        EVP_MD_CTX_free(hmac_ctx);

                printf("The HMAC is: ");
        for(int i = 0; i < hmac_len; i++)
			     printf("%02x", hmac_value[i]);
        printf("\n");


        // completely free all the cipher data
        CRYPTO_cleanup_all_ex_data();
        /* Remove error strings */
        ERR_free_strings();


	return 0;


}