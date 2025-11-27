#ifndef SIGN_H
#define SIGN_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "polyvec.h"
#include "poly.h"
// #include <stdbool.h>



#define SK_NUM 2000
#define MSG_NUM 200
#define GROUP_NUM 50
#define PARAM_NUM GROUP_NUM * MSG_NUM

typedef struct {
    polyveck w0;
    polyveck w1;
    polyvecl y;
    // poly tmp;
    // uint8_t sig[K*POLYW1_PACKEDBYTES+1];
    uint8_t *sig;
    bool isUsed;
    // uint8_t w1_bytes[64];
    // uint32_t kappa;
} precompute_param;

typedef struct {
    uint8_t *sk;
    uint8_t *rho;
    uint8_t *tr;
    polyvecl s1;
    polyveck s2;
    polyveck t0;
    // uint8_t K[64];
    // uint8_t index;
    precompute_param precomputed[PARAM_NUM];
} secret_key;

#define challenge DILITHIUM_NAMESPACE(challenge)
void challenge(poly *c, const uint8_t seed[SEEDBYTES]);

#define crypto_sign_keypair DILITHIUM_NAMESPACE(keypair)
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

#define crypto_sign_signature DILITHIUM_NAMESPACE(signature)
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk);

#define crypto_sign DILITHIUM_NAMESPACETOP
int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk);

#define crypto_sign_verify DILITHIUM_NAMESPACE(verify)
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *pk);

#define crypto_sign_open DILITHIUM_NAMESPACE(open)
int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk);

#define add_one_param DILITHIUM_NAMESPACE(add_one_param)
precompute_param * add_one_param(const uint8_t *sk, uint16_t nonce, 
                     uint16_t e_nonce, uint8_t *rhoprime, 
                     polyvecl mat[]);

#define precomputing DILITHIUM_NAMESPACE(precomputing)
void precomputing(const uint8_t *sk, size_t param_num);

#define crypto_sign_signature_with_precomputing DILITHIUM_NAMESPACE(signature_precomputing)
int crypto_sign_signature_with_precomputing(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk, uint8_t group_index);

#define crypto_sign_with_precomputing DILITHIUM_NAMESPACE(sign_precomputing)
int crypto_sign_with_precomputing(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk, uint8_t group_index);

#endif
