#ifndef HOSTAP_H
#define HOSTAP_H

typedef uint8_t u8;
typedef uint16_t u16;
struct crypto_bignum;
#define crypto_ec ec_group

#define SHA256_MAC_LEN 32
#define DRAGONFLY_MAX_ECC_PRIME_LEN 66
#define ETH_ALEN 6

struct sae_temporary_data {
	//u8 kck[SAE_KCK_LEN];
	struct crypto_bignum *own_commit_scalar;
	struct crypto_bignum *own_commit_element_ffc;
	struct crypto_ec_point *own_commit_element_ecc;
	struct crypto_bignum *peer_commit_element_ffc;
	struct crypto_ec_point *peer_commit_element_ecc;
	struct crypto_ec_point *pwe_ecc;
	struct crypto_bignum *pwe_ffc;
	struct crypto_bignum *sae_rand;
	struct crypto_ec *ec;
	int prime_len;
	//const struct dh_group *dh;
	const struct crypto_bignum *prime;
	const struct crypto_bignum *order;
	struct crypto_bignum *prime_buf;
	struct crypto_bignum *order_buf;
	//struct wpabuf *anti_clogging_token;
	char *pw_id;
	int vlan_id;
	u8 bssid[ETH_ALEN];
};

struct sae_data {
	//enum sae_state state;
	u16 send_confirm;
	//u8 pmk[SAE_PMK_LEN];
	//u8 pmkid[SAE_PMKID_LEN];
	struct crypto_bignum *peer_commit_scalar;
	int group;
	unsigned int sync; /* protocol instance variable: Sync */
	u16 rc; /* protocol instance variable: Rc (received send-confirm) */
	struct sae_temporary_data *tmp;
};

struct sae_data * sae_data_init(int group_id);
void sae_data_free(struct sae_data *sae);

extern int hostap_iteration_found;
extern int hostap_num_bighashes;

int dragonfly_get_random_qr_qnr(const struct crypto_bignum *prime,
				struct crypto_bignum **qr,
				struct crypto_bignum **qnr);
int sae_test_pwd_seed_ecc_hostap(struct sae_data *sae, const u8 *pwd_seed,
				 const u8 *prime, const u8 *qr, const u8 *qnr,
				 u8 *pwd_value);
int sae_derive_pwe_ecc_hostap(struct sae_data *sae, const u8 *addr1,
			      const u8 *addr2, const u8 *password,
			      size_t password_len, const char *identifier);

#endif // HOSTAP_H
