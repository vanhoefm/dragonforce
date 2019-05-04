// Possible optimizations:
// - First determine which passwords less than X loops. These can then be quickly dropped.
// - Or first determine which passwords require more than X loops, so they can then be dropped?
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <getopt.h>

#include <openssl/bn.h>
#include <openssl/sha.h>

#include <list>
#include <string>
#include <algorithm>
#include <vector>
#include <set>

#include "crypto.h"
#include "sae.h"
#include "hostap.h"

// ========================================== Main simulation function ==========================================

static void next_macaddr(uint8_t *macaddr)
{
	for (int i = 5; i >= 0; i--)
		if (macaddr[i]++ != 0)
			break;
}

// A1=c4:e9:84:db:fb:7b A2=00:8e:f2:7d:8b:05

static void simulate_brainpool_experiments(int group_id)
{
	struct sae_data *sae = sae_data_init(group_id);
	uint8_t macaddr1[6] = {0xc4, 0xe9, 0x84, 0xdb, 0xfb, 0x7b};
	uint8_t macaddr2[6] = {0x00, 0x8e, 0xf2, 0x7d, 0x8b, 0x00};
	const char *password = "abcdefgh";
	int num_tests = 1000;
	struct timespec time_start, time_end;

	for (int macaddr = 0; macaddr < 20; ++macaddr)
	{
		clock_gettime(CLOCK_MONOTONIC, &time_start);

		for (int i = 0; i < num_tests; ++i) {
			macaddr2[5] = macaddr;
			sae_derive_pwe_ecc_hostap(sae, macaddr1, macaddr2, (const u8*)password, strlen(password), NULL);
		}
		clock_gettime(CLOCK_MONOTONIC, &time_end);
		int elapsed_milliseconds = (time_end.tv_sec - time_start.tv_sec) * 1000 + (time_end.tv_nsec / 1000000 - time_start.tv_nsec / 1000000);

		hostap_iteration_found = 0;
		hostap_num_bighashes = 0;
		sae_derive_pwe_ecc_hostap(sae, macaddr1, macaddr2, (const u8*)password, strlen(password), NULL);

		printf("Elapsed time for macaddr %02X: %d/%d => %d ms\n", macaddr, hostap_num_bighashes, hostap_iteration_found - 1, elapsed_milliseconds);
	}
}

static void simulate_brainpool_timings(int group_id)
{
	struct sae_data *sae = sae_data_init(group_id);
	uint8_t macaddr1[6] = {0x00, 0x10, 0x20, 0x30, 0x40, 0x50};
	uint8_t macaddr2[6] = {0x00, 0x10, 0x20, 0x30, 0x40, 0x51};
	uint8_t pwd_seed[1024] = {0};
	uint8_t pwd_value[1024] = {0};
	u8 prime[SAE_MAX_ECC_PRIME_LEN];
	struct crypto_bignum *qr = NULL, *qnr = NULL;
	u8 qr_bin[SAE_MAX_ECC_PRIME_LEN];
	u8 qnr_bin[SAE_MAX_ECC_PRIME_LEN];
	const char *password = "hello123";
	int num_tests = 1000000;
	struct timespec time_start, time_end;

	if (crypto_bignum_to_bin((const BIGNUM*)sae->tmp->prime, prime, sizeof(prime),
				 sae->tmp->prime_len) < 0)
		printf("ERROR in %s\n", __FUNCTION__);

	if (dragonfly_get_random_qr_qnr(sae->tmp->prime, &qr, &qnr) < 0 ||
	    crypto_bignum_to_bin((const BIGNUM*)qr, qr_bin, sizeof(qr_bin), sae->tmp->prime_len) < 0 ||
	    crypto_bignum_to_bin((const BIGNUM*)qnr, qnr_bin, sizeof(qnr_bin), sae->tmp->prime_len) < 0)
		printf("ERROR in %s\n", __FUNCTION__);

	do {
		hostap_num_bighashes = 0;
		pwd_seed[0]++;
		sae_test_pwd_seed_ecc_hostap(sae, pwd_seed, 
				 prime, qr_bin, qnr_bin,
				 pwd_value);
	} while(hostap_num_bighashes != 0);

	clock_gettime(CLOCK_MONOTONIC, &time_start);

	for (int i = 0; i < num_tests; ++i) {
		sae_test_pwd_seed_ecc_hostap(sae, pwd_seed, 
				 prime, qr_bin, qnr_bin,
				 pwd_value);
	}

	clock_gettime(CLOCK_MONOTONIC, &time_end);
	int elapsed_milliseconds = (time_end.tv_sec - time_start.tv_sec) * 1000 + (time_end.tv_nsec / 1000000 - time_start.tv_nsec / 1000000);

	printf("Elapsed time for %d hash >= prime: %d ms\n", num_tests, elapsed_milliseconds);
}


static void simulate_brainpool(int group_id)
{
	struct sae_data *sae = sae_data_init(group_id);
	uint8_t macaddr1[6] = {0x00, 0x10, 0x20, 0x30, 0x40, 0x50};
	uint8_t macaddr2[6] = {0x00, 0x10, 0x20, 0x30, 0x40, 0x51};
	const char *password = "hello123";
	int num_found_first = 0;
	int max_iteration_found = 0;
	int num_tests = 10000;

	for (int i = 0; i < num_tests; ++i) {
		next_macaddr(macaddr1);
		int rval = sae_derive_pwe_ecc_hostap(sae, macaddr1, macaddr2, (const u8*)password, strlen(password), NULL);

		//printf("Iteration found: %d\n", hostap_iteration_found);

		if (hostap_iteration_found == 1)
			num_found_first++;

		if (hostap_iteration_found > max_iteration_found)
			max_iteration_found = hostap_iteration_found;
	}

	printf("Found in first iteration: %d / %d = %lf\n", num_found_first, num_tests, (double)num_found_first / num_tests);
	printf("Maximum iteration found: %d\n", max_iteration_found);
}

// ========================================== Main function ==========================================

struct options {
	int group_id;
} opt;

int main(int argc, char *argv[])
{
	if (test_ecc() < 0)
		exit(1);

	int c;

	while (1)
	{
		static struct option long_options[] =
		{
			{"group", required_argument, 0, 'g'},
			{0, 0, 0, 0}
		};
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long(argc, argv, "msf:d:g:", long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c)
		{
		case 'g':
			opt.group_id = atoi(optarg);
			break;

		default:
			abort();
		}
	}

	// Set default arguments
	if (opt.group_id == 0)
		opt.group_id = 29;

	simulate_brainpool_experiments(28);
	//simulate_brainpool_timings(opt.group_id);
	//simulate_brainpool(opt.group_id);

	return 0;
}

