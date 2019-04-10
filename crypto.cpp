#include <stdint.h>
#include <string.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "crypto.h"

static inline void WPA_PUT_LE16(uint8_t *a, uint16_t val)
{
	a[1] = val >> 8;
	a[0] = val & 0xff;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
HMAC_CTX *HMAC_CTX_new()
{
	static HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	return &ctx;
}

void HMAC_CTX_free(HMAC_CTX *ctx)
{
	HMAC_CTX_cleanup(ctx);
}
#endif

int hmac_vector_sha256(const uint8_t *key, size_t key_len, size_t num_elem,
		       const uint8_t *addr[], const size_t len[], uint8_t *mac)
{
	unsigned int mdlen = 32;
	HMAC_CTX *ctx;
	size_t i;
	int res;

	// TODO: Maybe we can reuse the context to increase performance?
	ctx = HMAC_CTX_new();
	if (!ctx) {
		fprintf(stderr, "%s: HMAC_CTX_new failed\n", __FUNCTION__);
		exit(1);
	}

	res = HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), NULL);
	if (res != 1) {
		HMAC_CTX_free(ctx);
		fprintf(stderr, "%s: HMAC_Init_ex failed\n", __FUNCTION__);
		exit(1);
	}

	for (i = 0; i < num_elem; i++)
		HMAC_Update(ctx, addr[i], len[i]);

	res = HMAC_Final(ctx, mac, &mdlen);
	if (res != 1) {
		HMAC_CTX_free(ctx);
		fprintf(stderr, "%s: HMAC_Final failed\n", __FUNCTION__);
		exit(1);
	}

	HMAC_CTX_free(ctx);
	return 1;
}

/**
 * sha256_prf_bits - IEEE Std 802.11-2012, 11.6.1.7.2 Key derivation function
 * @key: Key for KDF
 * @key_len: Length of the key in bytes
 * @label: A unique label for each purpose of the PRF
 * @data: Extra data to bind into the key
 * @data_len: Length of the data
 * @buf: Buffer for the generated pseudo-random key
 * @buf_len: Number of bits of key to generate
 * Returns: 0 on success, -1 on failure
 *
 * This function is used to derive new, cryptographically separate keys from a
 * given key. If the requested buf_len is not divisible by eight, the least
 * significant 1-7 bits of the last octet in the output are not part of the
 * requested output.
 */
int sha256_prf_bits(const uint8_t *key, size_t key_len, const char *label,
		    const uint8_t *data, size_t data_len, uint8_t *buf,
		    size_t buf_len_bits)
{
	uint16_t counter = 1;
	size_t pos, plen;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	const uint8_t *addr[4];
	size_t len[4];
	uint8_t counter_le[2], length_le[2];
	size_t buf_len = (buf_len_bits + 7) / 8;

	addr[0] = counter_le;
	len[0] = 2;
	addr[1] = (uint8_t *) label;
	len[1] = strlen(label);
	addr[2] = data;
	len[2] = data_len;
	addr[3] = length_le;
	len[3] = sizeof(length_le);

	WPA_PUT_LE16(length_le, buf_len_bits);
	pos = 0;
	while (pos < buf_len) {
		plen = buf_len - pos;
		WPA_PUT_LE16(counter_le, counter);
		if (plen >= SHA256_DIGEST_LENGTH) {
			hmac_vector_sha256(key, key_len, 4, addr, len, &buf[pos]);
			pos += SHA256_DIGEST_LENGTH;
		} else {
			hmac_vector_sha256(key, key_len, 4, addr, len, hash);
			memcpy(&buf[pos], hash, plen);
			pos += plen;
			break;
		}
		counter++;
	}

	/*
	 * Mask out unused bits in the last octet if it does not use all the
	 * bits.
	 */
	if (buf_len_bits % 8) {
		uint8_t mask = 0xff << (8 - buf_len_bits % 8);
		buf[pos - 1] &= mask;
	}

	return 0;
}

int crypto_bignum_to_bin(const BIGNUM *a, uint8_t *buf, size_t buflen, size_t padlen)
{
	int num_bytes, offset;

	if (padlen > buflen) {
		fprintf(stderr, "%s: padlen > buflen\n");
		exit(1);
	}

	num_bytes = BN_num_bytes((const BIGNUM *) a);
	if ((size_t) num_bytes > buflen) {
		fprintf(stderr, "%s: num_bytes > buflen\n");
		exit(1);
	}

	if (padlen > (size_t) num_bytes)
		offset = padlen - num_bytes;
	else
		offset = 0;

	memset(buf, 0, offset);
	BN_bn2bin((const BIGNUM *) a, buf + offset);

	return num_bytes + offset;
}


