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

#include "crypto.h"
#include "sae.h"
#include "partitioning.h"
#include "passwordlist.h"

void read_passwords(const char *filename, std::list<std::string> &passwords)
{
	FILE *fp = fopen(filename, "r");
	char line[256];

	while (fgets(line, sizeof(line), fp) != NULL)
		passwords.push_front(std::string(line));

	printf("Read %d passwords from %s\n", passwords.size(), filename);

	fclose(fp);
}


// ========================================== Micro Benchmarks ==========================================

void next_password(uint8_t password[16])
{
	int index = 15;
	while (index >= 0 && ++password[index] == 0)
		index -= 1;
}

void benchmark_micro_ffc(int group_id)
{
	uint8_t password[16];
	uint8_t addr1[6], addr2[6];
	const struct dh_group *dh = get_dh_group(group_id);

	for (int i = 0; i < 400000; ++i)
	{
		next_password(password);

		// Execute a single quadratic residue test
		sae_num_elemtests_ffc_iteration(dh, addr1, addr2, password, sizeof(password), 1);
	}
}


void benchmark_micro_ecc(int group_id = 19)
{
	uint8_t password[16];
	uint8_t addr1[6], addr2[6];
	const struct ec_group *ec = get_ec_group(group_id);
	uint8_t pwd_seed[SHA256_DIGEST_LENGTH];

	for (int i = 0; i < 1000000; ++i)
	{
		next_password(password);

		// Execute a single quadratic residue test
		sae_num_elemtests_ecc_iteration(ec, addr1, addr2, password, sizeof(password), pwd_seed, 1);
	}
}

void benchmark_micro(int group_id)
{

	struct timespec start, stop;
	unsigned long long accum;

	if (clock_gettime(CLOCK_REALTIME, &start) == -1) {
		perror("clock gettime");
		exit(1);
	}

	if (group_id >= 22 && group_id <= 24)
		benchmark_micro_ffc(group_id);
	else
		benchmark_micro_ecc(group_id);

	if (clock_gettime(CLOCK_REALTIME, &stop) == -1) {
		perror("clock gettime");
		exit(1);
	}

	accum = (stop.tv_sec - start.tv_sec) * 1000000000
		+ (stop.tv_nsec - start.tv_nsec);
	printf("%lld nanoseconds\n", accum);
}


// ========================================== Brainpool Timing Attacks ==========================================

// 1. Read the relationships from a file. Previously we only simulated this. Should we simulate again?
// 2. [DONE!] Read all the passwords from a file. Create a class for this, which can decide to read all at once or in chunks or one by one.
// 3. Simulate the MAC addresses one by one, and for each one compare the relationships we can now check with the one we measured.

// We need:
// - Function to extract when ECC was found, and how many hashchecks failed.
// - For every single iteration, we can already filter the variance relationships. But is this worth the performance increase?
//   We should just check a single MAC address. Then estimate performance based on MAC addresses that we have. We can run a
//   more performant Legendre test, no need for blinding, don't even need constant time Legendre computation.

// ========================================== Main function ==========================================

struct options {
	int group_id;
	int micro;
	int smart;
	const char *dictionary_file;
	int dictionary_size;
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
			{"micro", no_argument, 0, 'm'},
			{"smart", no_argument, 0, 's'},
			{"group", required_argument, 0, 'g'},
			{"dictionary", required_argument, 0, 'f'},
			{"dictionary-size", required_argument, 0, 'd'},
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
		case 'm':
			opt.micro = 1;
			break;

		case 's':
			opt.smart = 1;
			break;

		case 'f':
			opt.dictionary_file = optarg;
			break;

		case 'd':
			opt.dictionary_size = atoi(optarg);
			break;

		case 'g':
			opt.group_id = atoi(optarg);
			break;

		default:
			abort();
		}
	}

	// Check conflicting arguments
	if (opt.micro && opt.smart) {
		printf("Cannot use --micro and --smart flags at the same time\n");
		return 1;
	} else if (opt.dictionary_file != NULL && opt.dictionary_size > 0) {
		printf("Cannot use --dictionary and --dictionary-size at the same time\n");
		return 1;
	}

	// Set default arguments
	if (opt.group_id == 0)
		opt.group_id = 19;
	if (opt.dictionary_file == NULL && opt.dictionary_size == 0)
		opt.dictionary_size = 1000;

	if (opt.micro)
	{
		benchmark_micro(opt.group_id);
	}
	else
	{
		// Based on the options, load/generate a dictionary of passwords
		std::list<std::string> passwords;
		int group_id = 22;
		char outfile[256];

		if (opt.dictionary_file) {
			read_passwords(opt.dictionary_file, passwords);
			//passwords = PasswordFile(opt.dictionary_file);
		} else {
			simulate_dictionary(opt.dictionary_size, passwords);
			//passwords = PasswordGenerator(opt.dictionary_size);
		}

		printf("Simulating group %d\n", opt.group_id);
		printf("Using a dictionary of size %d\n", passwords.size());
		sprintf(outfile, "simulation_results_%d.py", time(NULL));
		SimulationResults results = simulate_partition_attack(outfile, passwords, opt.group_id);
	}

	return 0;
}

