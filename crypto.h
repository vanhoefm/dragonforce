#ifndef crypto_h
#define crypto_h

#include <stdint.h>

#include <openssl/ec.h>
#include <openssl/bn.h>

#define SAE_MAX_ECC_PRIME_LEN 66

struct dh_group {
	int id;
	const uint8_t *generator;
	size_t generator_len;
	const uint8_t *prime;
	size_t prime_len;
	const uint8_t *order;
	size_t order_len;
	unsigned int safe_prime:1;
};

struct ec_group {
	EC_GROUP *group;
	int nid;
	BN_CTX *bnctx;
	BIGNUM *prime;
	size_t prime_len;
	BIGNUM *order;
	BIGNUM *a;
	BIGNUM *b;
};

const struct dh_group * get_dh_group(int id);

void ec_group_deinit(struct ec_group *e);
struct ec_group *ec_group_init(int group);
struct ec_group * get_ec_group(int group);

int crypto_bignum_legendre(const BIGNUM *a, const BIGNUM *p);
BIGNUM * crypto_ec_point_compute_y_sqr(const struct ec_group *e, const BIGNUM *x);
int is_quadratic_residue(const struct ec_group *e, const uint8_t *prime, const BIGNUM *y_sqr);

int hmac_vector_sha256(const uint8_t *key, size_t key_len, size_t num_elem,
		       const uint8_t *addr[], const size_t len[], uint8_t *mac);
int sha256_prf_bits(const uint8_t *key, size_t key_len, const char *label,
		    const uint8_t *data, size_t data_len, uint8_t *buf,
		    size_t buf_len_bits);
int crypto_bignum_to_bin(const BIGNUM *a, uint8_t *buf, size_t buflen, size_t padlen);

#endif // crypto_h
