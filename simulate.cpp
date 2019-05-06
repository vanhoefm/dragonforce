// Possible optimizations:
// - First determine which passwords less than X loops. These can then be quickly dropped.
// - Or first determine which passwords require more than X loops, so they can then be dropped?
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <string>
#include <algorithm>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "sae.h"
#include "simulate.h"


void rand_bytes(unsigned char *buffer, size_t len)
{
	RAND_bytes(buffer, len);
}


void simulate_dictionary(int size, std::list<std::string> &passwords)
{
	char buffer[200];

	for (int i = 0; i < size; ++i)
	{
		snprintf(buffer, sizeof(buffer), "password%d", i);
		passwords.push_front(std::string(buffer));
	}
}

// ----------------------------------------------------------------------------------------------------

/**
 * This corresponds to the remote timing attack.
 */
void simulate_online_attack_ffc(int group_id, const char *password, int requested_elemtests, IterationData &data)
{
	const struct dh_group *dh;
	int curr_elemtests = 0;

	data.group_id = group_id;
	dh = get_dh_group(data.group_id);

	// Generate random AP address
	rand_bytes(data.bssid, 6);

	for (int i = 0; curr_elemtests < requested_elemtests; ++i)
	{
		// Generate random client MAC address
		unsigned char macaddr[6];
		rand_bytes(macaddr, 6);

		// Determine number of loops under it
		int new_elemtests = sae_num_elemtests_ffc(dh, data.bssid, macaddr, (uint8_t*)password,
							    strlen(password));

		// Note: we must not ignore a case with a too high iteration count.
		// Because that would no longer make the sampling random, as it generates
		// less iterantion results that need an extra loop, causing a bias.

		// Add iterations were element wasn't found
		for (int i = 1; i < new_elemtests && curr_elemtests < requested_elemtests; ++i) {
			data.add_iteration_result(macaddr, i, false);
			curr_elemtests += 1;
		}

		// In the last iteration it was found
		if (curr_elemtests < requested_elemtests) {
			data.add_iteration_result(macaddr, new_elemtests, true);
			curr_elemtests += 1;
		}
	}
}


/**
 * This corresponds to the cache-based attack that determines the result of the first iteration.
 */
void simulate_online_attack_ecc(int group_id, const char *password, int iterations, IterationData &data)
{
	const struct ec_group *ec;
	uint8_t pwd_seed[SHA256_DIGEST_LENGTH];
	int total_iterations = 0;

	data.group_id = group_id;
	ec = get_ec_group(data.group_id);

	// Generate random AP address
	rand_bytes(data.bssid, 6);

	for (int i = 0; i < iterations; ++i)
	{
		// Generate random client MAC address
		unsigned char macaddr[6];
		rand_bytes(macaddr, 6);

		// Check whether the first iteration finds the group element or not
		int rval = sae_num_elemtests_ecc_iteration(ec, data.bssid, macaddr, (uint8_t*)password,
							    strlen(password), pwd_seed, 1);

		data.add_iteration_result(macaddr, 1, rval == 1);
	}
}


void simulate_online_attack(int group_id, const char *password, int iterations, IterationData &data)
{
	// TODO: Better detect difference between ECC and FFC
	if (group_id >= 22 && group_id <= 24)
		simulate_online_attack_ffc(group_id, password, iterations, data);
	else
		simulate_online_attack_ecc(group_id, password, iterations, data);
}


// ----------------------------------------------------------------------------

/**
 * This corresponds to the cache-based attack that determines the result of the first iteration.
 */
void simulate_online_attack_ecc_pwfilter(int group_id, const char *password, int iterations, const char *filename)
{
	const struct ec_group *ec = get_ec_group(group_id);
	uint8_t pwd_seed[SHA256_DIGEST_LENGTH];
	int total_iterations = 0;
	uint8_t bssid[6];

	// Generate random AP address
	rand_bytes(bssid, 6);

	FILE *fp = fopen(filename, "w");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open %s for writing: ", filename);
		perror("");
		return;
	}

	fprintf(fp, "BSSID %02X:%02X:%02X:%02X:%02X:%02X\n", bssid[0], bssid[1],
		bssid[2], bssid[3], bssid[4], bssid[5]);
	fprintf(fp, "Group %d\n", group_id);

	for (int i = 0; i < iterations; ++i)
	{
		// Generate random client MAC address
		unsigned char macaddr[6];
		rand_bytes(macaddr, 6);

		// Check whether the first iteration finds the group element or not
		int rval = sae_num_elemtests_ecc_iteration(ec, bssid, macaddr, (uint8_t*)password,
							    strlen(password), pwd_seed, 1);
		bool found = rval == 1;

		fprintf(fp, "ElementTest %02X:%02X:%02X:%02X:%02X:%02X %d %d\n", macaddr[0],
			macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5], 1, found);
	}

	fclose(fp);
}


