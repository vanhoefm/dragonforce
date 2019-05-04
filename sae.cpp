// Possible optimizations:
// - First determine which passwords less than X loops. These can then be quickly dropped.
// - Or first determine which passwords require more than X loops, so they can then be dropped?
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include <openssl/bn.h>
#include <openssl/sha.h>

#include "crypto.h"
#include "sae.h"

#define ETH_HW_LEN 6
#define SAE_MAX_PRIME_LEN 512

// ======================= Efficient functions for brute-forcing ========================

void buf_shift_right(uint8_t *buf, size_t len, size_t bits)
{
	size_t i;
	for (i = len - 1; i > 0; i--)
		buf[i] = (buf[i - 1] << (8 - bits)) | (buf[i] >> bits);
	buf[0] >>= bits;
}


void sae_pwd_seed_key(const uint8_t *addr1, const uint8_t *addr2, uint8_t *key)
{
	if (memcmp(addr1, addr2, ETH_HW_LEN) > 0) {
		memcpy(key, addr1, ETH_HW_LEN);
		memcpy(key + ETH_HW_LEN, addr2, ETH_HW_LEN);
	} else {
		memcpy(key, addr2, ETH_HW_LEN);
		memcpy(key + ETH_HW_LEN, addr1, ETH_HW_LEN);
	}
}


static int sae_test_pwd_seed_ffc(const struct dh_group *dh, const uint8_t *pwd_seed)
{
	uint8_t pwd_value[SAE_MAX_PRIME_LEN];
	size_t bits = dh->prime_len * 8;

	/* pwd-value = KDF-z(pwd-seed, "SAE Hunting and Pecking", p) */
	if (sha256_prf_bits(pwd_seed, SHA256_DIGEST_LENGTH, "SAE Hunting and Pecking",
			    dh->prime, dh->prime_len, pwd_value,
			    bits) < 0) {
		fprintf(stderr, "sha256_prf_bits failed\n");
		exit(1);
	}

	if (memcmp(pwd_value, dh->prime, dh->prime_len) >= 0)
		return 0;

	// TODO: The exponentiation practically always results in P > 1 (??).
	//       So need to execute and verify it!

	return 1;
}

bool sae_num_elemtests_ffc_iteration(const struct dh_group *dh, const uint8_t *addr1,
				 const uint8_t *addr2, const uint8_t *password,
				 size_t password_len, int iteration)
{
	uint8_t pwd_seed[SHA256_DIGEST_LENGTH];
	uint8_t addrs[2 * ETH_HW_LEN];
	const uint8_t *addr[2];
	uint8_t counter;
	size_t len[2];
	size_t num_elem;
	int res;


	/*
	 * H(salt, ikm) = HMAC-SHA256(salt, ikm)
	 * pwd-seed = H(MAX(STA-A-MAC, STA-B-MAC) || MIN(STA-A-MAC, STA-B-MAC),
	 *              password [|| identifier] || counter)
	 */
	sae_pwd_seed_key(addr1, addr2, addrs);

	addr[0] = password;
	len[0] = password_len;
	addr[1] = &counter;
	len[1] = sizeof(counter);
	num_elem = 2;

	counter = iteration;
	hmac_vector_sha256(addrs, sizeof(addrs), num_elem,
			   addr, len, pwd_seed);
	return sae_test_pwd_seed_ffc(dh, pwd_seed);
}


int sae_num_elemtests_ffc(const struct dh_group *dh, const uint8_t *addr1,
			   const uint8_t *addr2, const uint8_t *password,
			   size_t password_len)
{
	int counter = 1;
	for (int counter = 1; counter < 256; counter++) {
		bool found = sae_num_elemtests_ffc_iteration(dh, addr1, addr2, password, password_len, counter);
		if (found)
			return counter;
	}

	return -1;
}


static int sae_test_pwd_seed_ecc(const struct ec_group *ec, const uint8_t *pwd_seed,
				 const uint8_t *prime)
{
	uint8_t pwd_value[SAE_MAX_ECC_PRIME_LEN];
	BIGNUM *y_sqr, *x_cand;
	int res;
	size_t bits;

	//wpa_hexdump_key(MSG_DEBUG, "SAE: pwd-seed", pwd_seed, SHA256_MAC_LEN);

	/* pwd-value = KDF-z(pwd-seed, "SAE Hunting and Pecking", p) */
	bits = BN_num_bits(ec->prime);
	sha256_prf_bits(pwd_seed, SHA256_DIGEST_LENGTH, "SAE Hunting and Pecking",
			    prime, ec->prime_len, pwd_value, bits);
	if (bits % 8)
		buf_shift_right(pwd_value, sizeof(pwd_value), 8 - bits % 8);
	//wpa_hexdump_key(MSG_DEBUG, "SAE: pwd-value", pwd_value, ec->prime_len);

	if (memcmp(pwd_value, prime, ec->prime_len) >= 0)
		return 0;

	x_cand = BN_bin2bn(pwd_value, ec->prime_len, NULL);
	if (!x_cand) {
		fprintf(stderr, "%s: BN_bin2bn failed\n", __FUNCTION__);
		exit(1);
	}

	y_sqr = crypto_ec_point_compute_y_sqr(ec, x_cand);
	if (!y_sqr) {
		fprintf(stderr, "%s: crypto_ec_point_compute_y_sqr failed\n", __FUNCTION__);
		exit(1);
	}

	res = is_quadratic_residue(ec, prime, y_sqr);
	BN_free(y_sqr);
	if (res <= 0) {
		BN_free(x_cand);
		return res;
	}

	BN_free(x_cand);
	return 1;
}


/**
 * Returns true if the element was found in this iteration, and false otherwise.
 */
bool sae_num_elemtests_ecc_iteration(const struct ec_group *ec, const uint8_t *addr1,
			   const uint8_t *addr2, const uint8_t *password,
			   size_t password_len, uint8_t pwd_seed[SHA256_DIGEST_LENGTH],
			   int iteration)
{
	uint8_t counter = iteration;
	uint8_t addrs[2 * ETH_HW_LEN];
	const uint8_t *addr[2];
	size_t len[2];
	size_t num_elem;
	uint8_t prime[SAE_MAX_ECC_PRIME_LEN];
	size_t prime_len;
	BIGNUM *x_cand;
	int res;

	prime_len = ec->prime_len;
	crypto_bignum_to_bin(ec->prime, prime, sizeof(prime), prime_len);

	/*
	 * H(salt, ikm) = HMAC-SHA256(salt, ikm)
	 * base = password [|| identifier]
	 * pwd-seed = H(MAX(STA-A-MAC, STA-B-MAC) || MIN(STA-A-MAC, STA-B-MAC),
	 *              base || counter)
	 */
	sae_pwd_seed_key(addr1, addr2, addrs);

	addr[0] = password;
	len[0] = password_len;
	addr[1] = &counter;
	len[1] = sizeof(counter);
	num_elem = 2;

	hmac_vector_sha256(addrs, sizeof(addrs), num_elem,
			   addr, len, pwd_seed);

	res = sae_test_pwd_seed_ecc(ec, pwd_seed, prime);
	return res > 0;
}


int test_ecc()
{
	// Perform some unit tests on MAC addresses to see if we get the correct x-coordinate
	const char *password = "wpa3-password";
	uint8_t addr1[] = "\x82\xad\x97\x91\x57\xd6";
	uint8_t addr2[] = "\x66\x2b\x48\xce\x46\xd2";
	const struct ec_group *ec = get_ec_group(19);
	uint8_t pwd_seed[SHA256_DIGEST_LENGTH];

	// Unit test 1: found in first iteration
	sae_num_elemtests_ecc_iteration(ec, addr1, addr2, (uint8_t*)password, strlen(password), pwd_seed, 1);
	if (0 != memcmp(pwd_seed,
			"\x0b\x32\x93\x1a\xd7\xd5\xc4\xf5\xc0\x4b\xa9\x14\x46\x42\xad\x04"
			"\x23\x62\xd4\x08\xc8\xf8\x64\x09\x39\x31\xbd\x16\x45\x18\x36\xa3",
			SHA256_DIGEST_LENGTH)) {
		fprintf(stderr, "Error in ECC PWE derivation algorithm (1)\n");
		return -1;
	}

	// Unit test 2: found in second iteration
	memcpy(addr1, "\x1e\x49\x18\x7a\xfd\x40", 6);
	sae_num_elemtests_ecc_iteration(ec, addr1, addr2, (uint8_t*)password, strlen(password), pwd_seed, 2);
	if (0 != memcmp(pwd_seed,
			"\x64\xff\x9b\x54\x3b\x52\xbb\xdd\x0b\xb6\x57\xff\x01\x1f\xec\xb6"
			"\x89\x0d\x64\x19\xc4\x8e\xf4\x86\x58\xc6\x74\x7e\x9b\x83\x70\x00",
			SHA256_DIGEST_LENGTH)) {
		fprintf(stderr, "Error in ECC PWE derivation algorithm (2)\n");
		return -1;
	}

	// Unit test 3: found in fourth iteration
	memcpy(addr1, "\x12\xe1\x24\x93\xbf\xe6", 6);
	sae_num_elemtests_ecc_iteration(ec, addr1, addr2, (uint8_t*)password, strlen(password), pwd_seed, 4);
	if (0 != memcmp(pwd_seed,
			"\x7c\xc0\x26\xf4\x49\x5e\x59\xc7\x86\xc7\x58\xb4\x82\xcb\x67\x75"
			"\x56\x0d\xd1\xcb\x0d\x1f\x35\xa9\x92\xc7\xd5\xf5\xbe\x93\xfb\xe4",
			SHA256_DIGEST_LENGTH)) {
		for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%02X", pwd_seed[i]);
		printf("\n");
		fprintf(stderr, "Error in ECC PWE derivation algorithm (4)\n");
		return -1;
	}

	return 0;
}

