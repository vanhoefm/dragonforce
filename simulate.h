#ifndef bruter_simulate_h
#define bruter_simulate_h

#include <string>
#include <list>
#include <algorithm>

class IterationResult {
public:
	unsigned char macaddr[6];
	int iteration;
	bool found;

	IterationResult(unsigned char *macaddr, int iteration, bool found) {
		memcpy(this->macaddr, macaddr, 6);
		this->iteration = iteration;
		this->found = found;
	}

	bool operator<(const IterationResult &other) const {
		return !this->found && other.found;
	}
};

class IterationData {
public:
	int group_id;
	unsigned char bssid[6];

	std::list<IterationResult> iterations;

	void add_iteration_result(unsigned char *macaddr, int iteration, bool found)
	{
		// WARNING: Using push_front would cause a bias in the data. This is because the
		// last IterationResult2 is more likely to be one where multiple iterations were
		// needed to find the group element. At least that's the case with our current
		// tatic where we generate a certain amount of iteration results, instead of
		// generating a certain amount of password deriviations.
		iterations.push_back(IterationResult(macaddr, iteration, found));
	}

	size_t num_iteration_results() const { return iterations.size(); }

	void sort_results()
	{
		iterations.sort();
	}
};

void simulate_dictionary(int size, std::list<std::string> &passwords);
void simulate_online_attack(int group_id, const char *password, int iterations, IterationData &data);

void simulate_online_attack_ecc_pwfilter(int group_id, const char *password, int iterations, const char *filename);

#endif // bruter_simulate_h
