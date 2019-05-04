#include <stdint.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>


#include "crypto.h"
#include "sae.h"
#include "hostap.h"

#define os_memset memset
#define os_malloc malloc
#define os_strlen strlen
#define os_free free
#define os_memcpy memcpy

int hostap_iteration_found = 0;
int hostap_num_bighashes = 0;

size_t crypto_ec_prime_len(struct crypto_ec *e);

struct sae_data * sae_data_init(int group_id)
{
	struct sae_data *sae = (struct sae_data *)malloc(sizeof(struct sae_data));
	memset(sae, 0, sizeof(*sae));

	sae->tmp = (struct sae_temporary_data*)malloc(sizeof(*sae->tmp));
	memset(sae->tmp, 0, sizeof(*sae->tmp));

	sae->tmp->ec = get_ec_group(group_id);;
	sae->tmp->prime_len = crypto_ec_prime_len(sae->tmp->ec);
	sae->tmp->prime = (const crypto_bignum*)sae->tmp->ec->prime;
	sae->tmp->pwe_ecc = NULL;

	return sae;
}

void sae_data_free(struct sae_data *sae)
{
	free(sae->tmp);
	free(sae);
}

static int openssl_digest_vector(const EVP_MD *type, size_t num_elem,
				 const u8 *addr[], const size_t *len, u8 *mac)
{
	EVP_MD_CTX *ctx;
	size_t i;
	unsigned int mac_len;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return -1;
	if (!EVP_DigestInit_ex(ctx, type, NULL)) {
		//wpa_printf(MSG_ERROR, "OpenSSL: EVP_DigestInit_ex failed: %s",
		//	   ERR_error_string(ERR_get_error(), NULL));
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	for (i = 0; i < num_elem; i++) {
		if (!EVP_DigestUpdate(ctx, addr[i], len[i])) {
			//wpa_printf(MSG_ERROR, "OpenSSL: EVP_DigestUpdate "
			//	   "failed: %s",
			//	   ERR_error_string(ERR_get_error(), NULL));
			EVP_MD_CTX_free(ctx);
			return -1;
		}
	}
	if (!EVP_DigestFinal(ctx, mac, &mac_len)) {
		//wpa_printf(MSG_ERROR, "OpenSSL: EVP_DigestFinal failed: %s",
		//	   ERR_error_string(ERR_get_error(), NULL));
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	EVP_MD_CTX_free(ctx);

	return 0;
}

int sha256_vector(size_t num_elem, const u8 *addr[], const size_t *len,
		  u8 *mac)
{
	return openssl_digest_vector(EVP_sha256(), num_elem, addr, len, mac);
}

/**
 * hmac_sha256_vector - HMAC-SHA256 over data vector (RFC 2104)
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash (32 bytes)
 * Returns: 0 on success, -1 on failure
 */
int hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem,
		       const u8 *addr[], const size_t *len, u8 *mac)
{
	unsigned char k_pad[64]; /* padding - key XORd with ipad/opad */
	unsigned char tk[32];
	const u8 *_addr[6];
	size_t _len[6], i;

	if (num_elem > 5) {
		/*
		 * Fixed limit on the number of fragments to avoid having to
		 * allocate memory (which could fail).
		 */
		return -1;
	}

        /* if key is longer than 64 bytes reset it to key = SHA256(key) */
        if (key_len > 64) {
		if (sha256_vector(1, &key, &key_len, tk) < 0)
			return -1;
		key = tk;
		key_len = 32;
        }

	/* the HMAC_SHA256 transform looks like:
	 *
	 * SHA256(K XOR opad, SHA256(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected */

	/* start out by storing key in ipad */
	os_memset(k_pad, 0, sizeof(k_pad));
	os_memcpy(k_pad, key, key_len);
	/* XOR key with ipad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x36;

	/* perform inner SHA256 */
	_addr[0] = k_pad;
	_len[0] = 64;
	for (i = 0; i < num_elem; i++) {
		_addr[i + 1] = addr[i];
		_len[i + 1] = len[i];
	}
	if (sha256_vector(1 + num_elem, _addr, _len, mac) < 0)
		return -1;

	os_memset(k_pad, 0, sizeof(k_pad));
	os_memcpy(k_pad, key, key_len);
	/* XOR key with opad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x5c;

	/* perform outer SHA256 */
	_addr[0] = k_pad;
	_len[0] = 64;
	_addr[1] = mac;
	_len[1] = SHA256_MAC_LEN;
	return sha256_vector(2, _addr, _len, mac);
}

size_t crypto_ec_prime_len_bits(struct crypto_ec *e)
{
	return BN_num_bits(e->prime);
}

size_t crypto_ec_prime_len(struct crypto_ec *e)
{
	return BN_num_bytes(e->prime);
}

const struct crypto_bignum * crypto_ec_get_prime(struct crypto_ec *e)
{
	return (const struct crypto_bignum *) e->prime;
}

struct crypto_ec_point * crypto_ec_point_init(struct crypto_ec *e)
{
	if (e == NULL)
		return NULL;
	return (struct crypto_ec_point *) EC_POINT_new(e->group);
}

struct crypto_bignum *
crypto_ec_point_compute_y_sqr(struct crypto_ec *e,
			      const struct crypto_bignum *x)
{
	BIGNUM *tmp, *tmp2, *y_sqr = NULL;

	tmp = BN_new();
	tmp2 = BN_new();

	/* y^2 = x^3 + ax + b */
	if (tmp && tmp2 &&
	    BN_mod_sqr(tmp, (const BIGNUM *) x, e->prime, e->bnctx) &&
	    BN_mod_mul(tmp, tmp, (const BIGNUM *) x, e->prime, e->bnctx) &&
	    BN_mod_mul(tmp2, e->a, (const BIGNUM *) x, e->prime, e->bnctx) &&
	    BN_mod_add_quick(tmp2, tmp2, tmp, e->prime) &&
	    BN_mod_add_quick(tmp2, tmp2, e->b, e->prime)) {
		y_sqr = tmp2;
		tmp2 = NULL;
	}

	BN_clear_free(tmp);
	BN_clear_free(tmp2);

	return (struct crypto_bignum *) y_sqr;
}

int crypto_ec_point_solve_y_coord(struct crypto_ec *e,
				  struct crypto_ec_point *p,
				  const struct crypto_bignum *x, int y_bit)
{
	if (!EC_POINT_set_compressed_coordinates_GFp(e->group, (EC_POINT *) p,
						     (const BIGNUM *) x, y_bit,
						     e->bnctx) ||
	    !EC_POINT_is_on_curve(e->group, (EC_POINT *) p, e->bnctx))
		return -1;
	return 0;
}

/**
 * const_time_fill_msb - Fill all bits with MSB value
 * @val: Input value
 * Returns: Value with all the bits set to the MSB of the input val
 */
static inline unsigned int const_time_fill_msb(unsigned int val)
{
	/* Move the MSB to LSB and multiple by -1 to fill in all bits. */
	return (val >> (sizeof(val) * 8 - 1)) * ~0U;
}

/**
 * const_time_select - Constant time unsigned int selection
 * @mask: 0 (false) or -1 (true) to identify which value to select
 * @true_val: Value to select for the true case
 * @false_val: Value to select for the false case
 * Returns: true_val if mask == -1, false_val if mask == 0
 */
static inline unsigned int const_time_select(unsigned int mask,
					     unsigned int true_val,
					     unsigned int false_val)
{
	return (mask & true_val) | (~mask & false_val);
}

/**
 * const_time_select_u8 - Constant time u8 selection
 * @mask: 0 (false) or -1 (true) to identify which value to select
 * @true_val: Value to select for the true case
 * @false_val: Value to select for the false case
 * Returns: true_val if mask == -1, false_val if mask == 0
 */
static inline u8 const_time_select_u8(u8 mask, u8 true_val, u8 false_val)
{
	return (u8) const_time_select(mask, true_val, false_val);
}

/**
 * const_time_select_int - Constant time int selection
 * @mask: 0 (false) or -1 (true) to identify which value to select
 * @true_val: Value to select for the true case
 * @false_val: Value to select for the false case
 * Returns: true_val if mask == -1, false_val if mask == 0
 */
static inline int const_time_select_int(unsigned int mask, int true_val,
					int false_val)
{
	return (int) const_time_select(mask, (unsigned int) true_val,
				       (unsigned int) false_val);
}

/* Returns: -1 if val is zero; 0 if val is not zero */
static inline unsigned int const_time_is_zero(unsigned int val)
{
	/* Set MSB to 1 for 0 and fill rest of bits with the MSB value */
	return const_time_fill_msb(~val & (val - 1));
}

/* Returns: -1 if a == b; 0 if a != b */
static inline unsigned int const_time_eq(unsigned int a, unsigned int b)
{
	return const_time_is_zero(a ^ b);
}

static inline int const_time_memcmp(const void *a, const void *b, size_t len)
{
	const u8 *aa = (const u8 *)a;
	const u8 *bb = (const u8 *)b;
	int diff, res = 0;
	unsigned int mask;

	if (len == 0)
		return 0;
	do {
		len--;
		diff = (int) aa[len] - (int) bb[len];
		mask = const_time_is_zero((unsigned int) diff);
		res = const_time_select_int(mask, res, diff);
	} while (len);

	return res;
}

/**
 * const_time_select_bin - Constant time binary buffer selection copy
 * @mask: 0 (false) or -1 (true) to identify which value to copy
 * @true_val: Buffer to copy for the true case
 * @false_val: Buffer to copy for the false case
 * @len: Number of octets to copy
 * @dst: Destination buffer for the copy
 *
 * This function copies the specified buffer into the destination buffer using
 * operations with identical memory access pattern regardless of which buffer
 * is being copied.
 */
static inline void const_time_select_bin(u8 mask, const u8 *true_val,
					 const u8 *false_val, size_t len,
					 u8 *dst)
{
	size_t i;

	for (i = 0; i < len; i++)
		dst[i] = const_time_select_u8(mask, true_val[i], false_val[i]);
}

struct crypto_bignum * crypto_bignum_init(void)
{
	return (struct crypto_bignum *) BN_new();
}

struct crypto_bignum * crypto_bignum_init_set(const u8 *buf, size_t len)
{
	BIGNUM *bn;

	bn = BN_bin2bn(buf, len, NULL);
	return (struct crypto_bignum *) bn;
}

void crypto_bignum_deinit(struct crypto_bignum *n, int clear)
{
	if (clear)
		BN_clear_free((BIGNUM *) n);
	else
		BN_free((BIGNUM *) n);
}

int crypto_bignum_is_odd(const struct crypto_bignum *a)
{
	return BN_is_odd((const BIGNUM *) a);
}

int crypto_bignum_mulmod(const struct crypto_bignum *a,
			 const struct crypto_bignum *b,
			 const struct crypto_bignum *c,
			 struct crypto_bignum *d)
{
	int res;

	BN_CTX *bnctx;

	bnctx = BN_CTX_new();
	if (bnctx == NULL)
		return -1;
	res = BN_mod_mul((BIGNUM *) d, (const BIGNUM *) a, (const BIGNUM *) b,
			 (const BIGNUM *) c, bnctx);
	BN_CTX_free(bnctx);

	return res ? 0 : -1;
}

int crypto_bignum_sub(const struct crypto_bignum *a,
		      const struct crypto_bignum *b,
		      struct crypto_bignum *c)
{
	return BN_sub((BIGNUM *) c, (const BIGNUM *) a, (const BIGNUM *) b) ?
		0 : -1;
}

int crypto_bignum_add(const struct crypto_bignum *a,
		      const struct crypto_bignum *b,
		      struct crypto_bignum *c)
{
	return BN_add((BIGNUM *) c, (const BIGNUM *) a, (const BIGNUM *) b) ?
		0 : -1;
}

int crypto_bignum_rand(struct crypto_bignum *r, const struct crypto_bignum *m)
{
	return BN_rand_range((BIGNUM *) r, (const BIGNUM *) m) == 1 ? 0 : -1;
}


static struct crypto_bignum *
dragonfly_get_rand_1_to_p_1(const struct crypto_bignum *prime)
{
	struct crypto_bignum *tmp, *pm1, *one;

	tmp = crypto_bignum_init();
	pm1 = crypto_bignum_init();
	one = crypto_bignum_init_set((const u8 *) "\x01", 1);
	if (!tmp || !pm1 || !one ||
	    crypto_bignum_sub(prime, one, pm1) < 0 ||
	    crypto_bignum_rand(tmp, pm1) < 0 ||
	    crypto_bignum_add(tmp, one, tmp) < 0) {
		crypto_bignum_deinit(tmp, 0);
		tmp = NULL;
	}

	crypto_bignum_deinit(pm1, 0);
	crypto_bignum_deinit(one, 0);
	return tmp;
}

int crypto_bignum_legendre(const struct crypto_bignum *a,
			   const struct crypto_bignum *p)
{
	BN_CTX *bnctx;
	BIGNUM *exp = NULL, *tmp = NULL;
	int res = -2;
	unsigned int mask;

	bnctx = BN_CTX_new();
	if (bnctx == NULL)
		return -2;

	exp = BN_new();
	tmp = BN_new();
	if (!exp || !tmp ||
	    /* exp = (p-1) / 2 */
	    !BN_sub(exp, (const BIGNUM *) p, BN_value_one()) ||
	    !BN_rshift1(exp, exp) ||
	    !BN_mod_exp_mont_consttime(tmp, (const BIGNUM *) a, exp,
				       (const BIGNUM *) p, bnctx, NULL))
		goto fail;

	/* Return 1 if tmp == 1, 0 if tmp == 0, or -1 otherwise. Need to use
	 * constant time selection to avoid branches here. */
	res = -1;
	mask = const_time_eq(BN_is_word(tmp, 1), 1);
	res = const_time_select_int(mask, 1, res);
	mask = const_time_eq(BN_is_zero(tmp), 1);
	res = const_time_select_int(mask, 0, res);

fail:
	BN_clear_free(tmp);
	BN_clear_free(exp);
	BN_CTX_free(bnctx);
	return res;
}

int random_get_bytes(void *buf, size_t len)
{
	return RAND_pseudo_bytes((unsigned char *)buf, len);
}

int dragonfly_get_random_qr_qnr(const struct crypto_bignum *prime,
				struct crypto_bignum **qr,
				struct crypto_bignum **qnr)
{
	*qr = *qnr = NULL;

	while (!(*qr) || !(*qnr)) {
		struct crypto_bignum *tmp;
		int res;

		tmp = crypto_bignum_init();
		if (!tmp || crypto_bignum_rand(tmp, prime) < 0)
			break;

		res = crypto_bignum_legendre(tmp, prime);
		if (res == 1 && !(*qr))
			*qr = tmp;
		else if (res == -1 && !(*qnr))
			*qnr = tmp;
		else
			crypto_bignum_deinit(tmp, 0);
	}

	if (*qr && *qnr)
		return 0;
	crypto_bignum_deinit(*qr, 0);
	crypto_bignum_deinit(*qnr, 0);
	*qr = *qnr = NULL;
	return -1;
}

int dragonfly_is_quadratic_residue_blind(struct crypto_ec *ec,
					 const u8 *qr, const u8 *qnr,
					 const struct crypto_bignum *val)
{
	struct crypto_bignum *r, *num, *qr_or_qnr = NULL;
	int check, res = -1;
	u8 qr_or_qnr_bin[DRAGONFLY_MAX_ECC_PRIME_LEN];
	const struct crypto_bignum *prime;
	size_t prime_len;
	unsigned int mask;

	prime = crypto_ec_get_prime(ec);
	prime_len = crypto_ec_prime_len(ec);

	/*
	 * Use a blinding technique to mask val while determining whether it is
	 * a quadratic residue modulo p to avoid leaking timing information
	 * while determining the Legendre symbol.
	 *
	 * v = val
	 * r = a random number between 1 and p-1, inclusive
	 * num = (v * r * r) modulo p
	 */
	r = dragonfly_get_rand_1_to_p_1(prime);
	if (!r)
		return -1;

	num = crypto_bignum_init();
	if (!num ||
	    crypto_bignum_mulmod(val, r, prime, num) < 0 ||
	    crypto_bignum_mulmod(num, r, prime, num) < 0)
		goto fail;

	/*
	 * Need to minimize differences in handling different cases, so try to
	 * avoid branches and timing differences.
	 *
	 * If r is odd:
	 * num = (num * qr) module p
	 * LGR(num, p) = 1 ==> quadratic residue
	 * else:
	 * num = (num * qnr) module p
	 * LGR(num, p) = -1 ==> quadratic residue
	 *
	 * mask is set to !odd(r)
	 */
	mask = const_time_is_zero(crypto_bignum_is_odd(r));
	const_time_select_bin(mask, qnr, qr, prime_len, qr_or_qnr_bin);
	qr_or_qnr = crypto_bignum_init_set(qr_or_qnr_bin, prime_len);
	if (!qr_or_qnr ||
	    crypto_bignum_mulmod(num, qr_or_qnr, prime, num) < 0)
		goto fail;
	/* branchless version of check = odd(r) ? 1 : -1, */
	check = const_time_select_int(mask, -1, 1);

	/* Determine the Legendre symbol on the masked value */
	res = crypto_bignum_legendre(num, prime);
	if (res == -2) {
		res = -1;
		goto fail;
	}
	/* branchless version of res = res == check
	 * (res is -1, 0, or 1; check is -1 or 1) */
	mask = const_time_eq(res, check);
	res = const_time_select_int(mask, 1, 0);
fail:
	crypto_bignum_deinit(num, 1);
	crypto_bignum_deinit(r, 1);
	crypto_bignum_deinit(qr_or_qnr, 1);
	return res;
}

// Latest version of the hash-to-curve algorithm used in Hostap
int sae_test_pwd_seed_ecc_hostap(struct sae_data *sae, const u8 *pwd_seed,
				 const u8 *prime, const u8 *qr, const u8 *qnr,
				 u8 *pwd_value)
{
	struct crypto_bignum *y_sqr, *x_cand;
	int res;
	size_t bits;

	//wpa_hexdump_key(MSG_DEBUG, "SAE: pwd-seed", pwd_seed, SHA256_MAC_LEN);

	/* pwd-value = KDF-z(pwd-seed, "SAE Hunting and Pecking", p) */
	bits = crypto_ec_prime_len_bits(sae->tmp->ec);
	if (sha256_prf_bits(pwd_seed, SHA256_MAC_LEN, "SAE Hunting and Pecking",
			    prime, sae->tmp->prime_len, pwd_value, bits) < 0)
		return -1;
	if (bits % 8)
		buf_shift_right(pwd_value, sae->tmp->prime_len, 8 - bits % 8);
	//wpa_hexdump_key(MSG_DEBUG, "SAE: pwd-value",
	//		pwd_value, sae->tmp->prime_len);

	if (const_time_memcmp(pwd_value, prime, sae->tmp->prime_len) >= 0) {
		if (!hostap_iteration_found)
			hostap_num_bighashes++;
		return 0;
	}

	x_cand = crypto_bignum_init_set(pwd_value, sae->tmp->prime_len);
	if (!x_cand)
		return -1;
	y_sqr = (struct crypto_bignum *)crypto_ec_point_compute_y_sqr(sae->tmp->ec, (const BIGNUM*)x_cand);
	crypto_bignum_deinit(x_cand, 1);
	if (!y_sqr)
		return -1;

	res = dragonfly_is_quadratic_residue_blind(sae->tmp->ec, qr, qnr,
						   y_sqr);
	crypto_bignum_deinit(y_sqr, 1);
	return res;
}


// Latest version of the hash-to-curve algorithm used in Hostap
int sae_derive_pwe_ecc_hostap(struct sae_data *sae, const u8 *addr1,
			      const u8 *addr2, const u8 *password,
			      size_t password_len, const char *identifier)
{
	u8 counter, k = 40;
	u8 addrs[2 * ETH_ALEN];
	const u8 *addr[3];
	size_t len[3];
	size_t num_elem;
	u8 *dummy_password, *tmp_password;
	int pwd_seed_odd = 0;
	u8 prime[SAE_MAX_ECC_PRIME_LEN];
	size_t prime_len;
	struct crypto_bignum *x = NULL, *qr = NULL, *qnr = NULL;
	u8 x_bin[SAE_MAX_ECC_PRIME_LEN];
	u8 x_cand_bin[SAE_MAX_ECC_PRIME_LEN];
	u8 qr_bin[SAE_MAX_ECC_PRIME_LEN];
	u8 qnr_bin[SAE_MAX_ECC_PRIME_LEN];
	int res = -1;
	u8 found = 0; /* 0 (false) or 0xff (true) to be used as const_time_*
		       * mask */

	hostap_iteration_found = 0;
	hostap_num_bighashes = 0;

	os_memset(x_bin, 0, sizeof(x_bin));

	dummy_password = (u8*)os_malloc(password_len);
	tmp_password = (u8*)os_malloc(password_len);
	if (!dummy_password || !tmp_password ||
	    random_get_bytes(dummy_password, password_len) < 0)
		goto fail;

	prime_len = sae->tmp->prime_len;
	if (crypto_bignum_to_bin((const BIGNUM*)sae->tmp->prime, prime, sizeof(prime),
				 prime_len) < 0)
		goto fail;

	/*
	 * Create a random quadratic residue (qr) and quadratic non-residue
	 * (qnr) modulo p for blinding purposes during the loop.
	 */
	if (dragonfly_get_random_qr_qnr(sae->tmp->prime, &qr, &qnr) < 0 ||
	    crypto_bignum_to_bin((const BIGNUM*)qr, qr_bin, sizeof(qr_bin), prime_len) < 0 ||
	    crypto_bignum_to_bin((const BIGNUM*)qnr, qnr_bin, sizeof(qnr_bin), prime_len) < 0)
		goto fail;

	//wpa_hexdump_ascii_key(MSG_DEBUG, "SAE: password",
	//		      password, password_len);
	//if (identifier)
	//	wpa_printf(MSG_DEBUG, "SAE: password identifier: %s",
	//		   identifier);

	/*
	 * H(salt, ikm) = HMAC-SHA256(salt, ikm)
	 * base = password [|| identifier]
	 * pwd-seed = H(MAX(STA-A-MAC, STA-B-MAC) || MIN(STA-A-MAC, STA-B-MAC),
	 *              base || counter)
	 */
	sae_pwd_seed_key(addr1, addr2, addrs);

	addr[0] = tmp_password;
	len[0] = password_len;
	num_elem = 1;
	if (identifier) {
		addr[num_elem] = (const u8 *) identifier;
		len[num_elem] = os_strlen(identifier);
		num_elem++;
	}
	addr[num_elem] = &counter;
	len[num_elem] = sizeof(counter);
	num_elem++;

	/*
	 * Continue for at least k iterations to protect against side-channel
	 * attacks that attempt to determine the number of iterations required
	 * in the loop.
	 */
	for (counter = 1; counter <= k || !found; counter++) {
		u8 pwd_seed[SHA256_MAC_LEN];

		if (counter > 200) {
			/* This should not happen in practice */
			//wpa_printf(MSG_DEBUG, "SAE: Failed to derive PWE");
			break;
		}

		//wpa_printf(MSG_DEBUG, "SAE: counter = %03u", counter);
		const_time_select_bin(found, dummy_password, password,
				      password_len, tmp_password);
		if (hmac_sha256_vector(addrs, sizeof(addrs), num_elem,
				       addr, len, pwd_seed) < 0)
			break;

		res = sae_test_pwd_seed_ecc_hostap(sae, pwd_seed,
					    prime, qr_bin, qnr_bin, x_cand_bin);
		const_time_select_bin(found, x_bin, x_cand_bin, prime_len,
				      x_bin);
		pwd_seed_odd = const_time_select_u8(
			found, pwd_seed_odd,
			pwd_seed[SHA256_MAC_LEN - 1] & 0x01);
		os_memset(pwd_seed, 0, sizeof(pwd_seed));
		if (res < 0)
			goto fail;
		/* Need to minimize differences in handling res == 0 and 1 here
		 * to avoid differences in timing and instruction cache access,
		 * so use const_time_select_*() to make local copies of the
		 * values based on whether this loop iteration was the one that
		 * found the pwd-seed/x. */

		if (!hostap_iteration_found && res == 1)
			hostap_iteration_found = counter;

		/* found is 0 or 0xff here and res is 0 or 1. Bitwise OR of them
		 * (with res converted to 0/0xff) handles this in constant time.
		 */
		found |= res * 0xff;
		//wpa_printf(MSG_DEBUG, "SAE: pwd-seed result %d found=0x%02x",
		//	   res, found);
	}

	if (!found) {
		//wpa_printf(MSG_DEBUG, "SAE: Could not generate PWE");
		res = -1;
		goto fail;
	}

	x = crypto_bignum_init_set(x_bin, prime_len);
	if (!x) {
		res = -1;
		goto fail;
	}

	if (!sae->tmp->pwe_ecc)
		sae->tmp->pwe_ecc = crypto_ec_point_init(sae->tmp->ec);
	if (!sae->tmp->pwe_ecc)
		res = -1;
	else
		res = crypto_ec_point_solve_y_coord(sae->tmp->ec,
						    sae->tmp->pwe_ecc, x,
						    pwd_seed_odd);
	if (res < 0) {
		/*
		 * This should not happen since we already checked that there
		 * is a result.
		 */
		//wpa_printf(MSG_DEBUG, "SAE: Could not solve y");
	}

fail:
	crypto_bignum_deinit(qr, 0);
	crypto_bignum_deinit(qnr, 0);
	os_free(dummy_password);
	//bin_clear_free(tmp_password, password_len);
	os_free(tmp_password);
	crypto_bignum_deinit(x, 1);
	os_memset(x_bin, 0, sizeof(x_bin));
	os_memset(x_cand_bin, 0, sizeof(x_cand_bin));

	return res;
}


