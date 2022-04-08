//Implementation with random numbers 

#include <stdio.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#define MAX_BYTES 32

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main (int argc, const char *argv[]){

    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_algorithms();

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = BN_new(); //public prime number
    BIGNUM *g = BN_new(); //public generator
    BIGNUM *a = BN_new(); //private alice
    BIGNUM *b = BN_new(); //private bob
    BIGNUM *a_calc = BN_new(); //number calculated by Alice with p,g,a
    BIGNUM *b_calc = BN_new(); //number calculated by Bob with p,g,b
    BIGNUM *a_key = BN_new(); //alice's key
    BIGNUM *b_key  = BN_new(); //bob's key (must be equal to Alice's key)


    BN_generate_prime_ex(p,32,0,NULL,NULL,NULL);
    BN_generate_prime_ex(g,32,0,NULL,NULL,NULL);
    BN_generate_prime_ex(a,32,0,NULL,NULL,NULL);
    BN_generate_prime_ex(b,32,0,NULL,NULL,NULL);

    BN_mod_exp(a_calc,g,a,p,ctx); //alice computes g^a mod p and trasmits it to Bob
    BN_mod_exp(b_calc,g,b,p,ctx); //bob computes g^b mod p and trasmits it to Alice

    BN_mod_exp(a_key,b_calc,a,p,ctx); //alice computes (g^b mod p)^a mod p
    BN_mod_exp(b_key,a_calc,b,p,ctx); //bob computes (g^a mod p)^b mod p


    if(!BN_cmp(a_key,b_key)){
        printf("DH key exchange successful!\n");
        printf("Alice's key is: ");
        BN_print_fp(stdout,a_key);
        printf("\n");
        printf("Bob's key is: ");
        BN_print_fp(stdout,b_key);
        printf("\n");
    }else{
        printf("Something gone wrong");
    }

    BN_free(p);
    BN_free(g);
    BN_free(a);
    BN_free(b);
    BN_free(a_calc);
    BN_free(b_calc);
    BN_free(a_key);
    BN_free(b_key);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
    
    return 0;

}