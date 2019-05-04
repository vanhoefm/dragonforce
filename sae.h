#ifndef bruter_sae_h
#define bruter_sae_h

#include <openssl/sha.h>

#include "crypto.h"

#define SAE_EXCEEDS_MAX_LOOPS	1
#define SAE_ERROR		2

void buf_shift_right(uint8_t *buf, size_t len, size_t bits);
void sae_pwd_seed_key(const uint8_t *addr1, const uint8_t *addr2, uint8_t *key);

bool sae_num_elemtests_ecc_iteration(const struct ec_group *ec, const uint8_t *addr1,
			   const uint8_t *addr2, const uint8_t *password,
			   size_t password_len, uint8_t pwd_seed[SHA256_DIGEST_LENGTH],
			   int iteration);


int sae_num_elemtests_ffc(const struct dh_group *dh, const uint8_t *addr1,
			   const uint8_t *addr2, const uint8_t *password,
			   size_t password_len);
bool sae_num_elemtests_ffc_iteration(const struct dh_group *dh, const uint8_t *addr1,
				 const uint8_t *addr2, const uint8_t *password,
				 size_t password_len, int iteration);


int test_ecc();

#endif // bruter_sae_h
