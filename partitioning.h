#ifndef PARTITIONING_H
#define PARTITIONING_H

#include <vector>

#include "simulate.h"


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
	static void write_vector(FILE *fp, const char *name, const std::vector<int> &list);
	static void print_vector(const char *varname, const std::vector<int> &list);

	SimulationResults(int max_elemtests) : simulations(0), used_elemtests(max_elemtests),
		simulated_elemtests(max_elemtests), used_timing_measurements(0)
	{
		/* nothing */
	}

	int write_to_file(const char *filename) const;
	void print() const;
};

int partition_attack(IterationData data, std::list<std::string> &passwords, int pws_to_remain = 1, int *out_total_used_tests = NULL, int *out_used_macaddrs = NULL);

SimulationResults simulate_partition_attack(const char *outfile, std::list<std::string> &passwords, int group_id = 22);
SimulationResults simulate_partition_attack_smart(const char *outfile, std::list<std::string> &passwords, int group_id = 22);

#endif // PARTITIONING_H
