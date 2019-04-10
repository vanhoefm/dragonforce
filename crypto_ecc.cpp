#include <stdint.h>
#include <string.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>

#include "crypto.h"

static struct ec_group *ec_group_cache[30];

void ec_group_deinit(struct ec_group *ec)
{
	BN_clear_free(ec->b);
	BN_clear_free(ec->a);
	BN_clear_free(ec->order);
	BN_clear_free(ec->prime);
	EC_GROUP_free(ec->group);
	BN_CTX_free(ec->bnctx);
	free(ec);
}

struct ec_group *ec_group_init(int group)
{
	struct ec_group *ec;
	int nid;

	/* Map from IANA registry for IKE D-H groups to OpenSSL NID */
	switch (group) {
	case 19:
		nid = NID_X9_62_prime256v1;
		break;
	case 20:
		nid = NID_secp384r1;
		break;
	case 21:
		nid = NID_secp521r1;
		break;
	case 25:
		nid = NID_X9_62_prime192v1;
		break;
	case 26:
		nid = NID_secp224r1;
		break;
#ifdef NID_brainpoolP224r1
	case 27:
		nid = NID_brainpoolP224r1;
		break;
#endif /* NID_brainpoolP224r1 */
#ifdef NID_brainpoolP256r1
	case 28:
		nid = NID_brainpoolP256r1;
		break;
#endif /* NID_brainpoolP256r1 */
#ifdef NID_brainpoolP384r1
	case 29:
		nid = NID_brainpoolP384r1;
		break;
#endif /* NID_brainpoolP384r1 */
#ifdef NID_brainpoolP512r1
	case 30:
		nid = NID_brainpoolP512r1;
		break;
#endif /* NID_brainpoolP512r1 */
	default:
		return NULL;
	}

	ec = (struct ec_group *)malloc(sizeof(*ec));
	if (ec == NULL)
		return NULL;

	ec->nid = nid;
	ec->bnctx = BN_CTX_new();
	ec->group = EC_GROUP_new_by_curve_name(nid);
	ec->prime = BN_new();
	ec->order = BN_new();
	ec->a = BN_new();
	ec->b = BN_new();
	if (ec->group == NULL || ec->bnctx == NULL || ec->prime == NULL ||
	    ec->order == NULL || ec->a == NULL || ec->b == NULL ||
	    !EC_GROUP_get_curve_GFp(ec->group, ec->prime, ec->a, ec->b, ec->bnctx) ||
	    !EC_GROUP_get_order(ec->group, ec->order, ec->bnctx)) {
		ec_group_deinit(ec);
		ec = NULL;
	}

	// TODO: Are all the parameters now initialized?

	ec->prime_len = BN_num_bytes(ec->prime);

	return ec;
}

struct ec_group * get_ec_group(int group)
{
	if (group >= 30) {
		fprintf(stderr, "ERROR: %s: unsupported group %d\n", __FUNCTION__, group);
		return NULL;
	}

	if (ec_group_cache[group] != NULL)
		return ec_group_cache[group];

	ec_group_cache[group] = ec_group_init(group);
	return ec_group_cache[group];
}

int crypto_bignum_legendre(const BIGNUM *a, const BIGNUM *p)
{
	BN_CTX *bnctx;
	BIGNUM *exp = NULL, *tmp = NULL;
	int res = -2;

	bnctx = BN_CTX_new();
	if (bnctx == NULL) {
		fprintf(stderr, "%s: BN_CTX_new failed\n", __FUNCTION__);
		exit(1);
	}

	exp = BN_new();
	tmp = BN_new();
	if (!exp || !tmp ||
	    /* exp = (p-1) / 2 */
	    !BN_sub(exp, (const BIGNUM *) p, BN_value_one()) ||
	    !BN_rshift1(exp, exp) ||
	    !BN_mod_exp(tmp, (const BIGNUM *) a, exp, (const BIGNUM *) p,
			bnctx))
		goto fail;

	if (BN_is_word(tmp, 1))
		res = 1;
	else if (BN_is_zero(tmp))
		res = 0;
	else
		res = -1;

fail:
	BN_clear_free(tmp);
	BN_clear_free(exp);
	BN_CTX_free(bnctx);
	return res;
}


BIGNUM * crypto_ec_point_compute_y_sqr(const struct ec_group *ec, const BIGNUM *x)
{
	BIGNUM *tmp, *tmp2, *y_sqr = NULL;

	tmp = BN_new();
	tmp2 = BN_new();

	/* y^2 = x^3 + ax + b */
	if (tmp && tmp2 &&
	    BN_mod_sqr(tmp, (const BIGNUM *) x, ec->prime, ec->bnctx) &&
	    BN_mod_mul(tmp, tmp, (const BIGNUM *) x, ec->prime, ec->bnctx) &&
	    BN_mod_mul(tmp2, ec->a, (const BIGNUM *) x, ec->prime, ec->bnctx) &&
	    BN_mod_add_quick(tmp2, tmp2, tmp, ec->prime) &&
	    BN_mod_add_quick(tmp2, tmp2, ec->b, ec->prime)) {
		y_sqr = tmp2;
		tmp2 = NULL;
	}

	BN_clear_free(tmp);
	BN_clear_free(tmp2);

	return (BIGNUM *) y_sqr;
}


int is_quadratic_residue(const struct ec_group *ec, const uint8_t *prime, const BIGNUM *y_sqr)
{
	int res = -1;

	res = crypto_bignum_legendre(y_sqr, ec->prime);

	return res == 1;
}

