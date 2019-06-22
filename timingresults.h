#ifndef timingresults_h
#define timingresults_h

#include <string>
#include <vector>
#include <map>

#include "passwordlist.h"

#define MAX_FILTERS 100

class PasswordSignature;
class MacAddrSimulation;
class PwFilter;

class PasswordSignature {
public:
	// General info
	const struct ec_group *ec;
	const struct dh_group *dh;
	uint8_t bssid[6];
	int group;

	// Current password being checked
	const char *password;
	int password_id;
	uint8_t pwd_seed[512];

	// For estimating brute-force costs
	int used_filters;
	int num_simulated_elemtests;
	int num_simulated_elemtests_hashtoobig;

private:
	// Only used during parsing
	std::map<std::string, MacAddrSimulation*> macaddr_map;
	PwFilter *filters[MAX_FILTERS];
	int num_filters;

	bool init_group(int groupid);
	bool parse_macaddr(const char *charaddr, uint8_t *macaddr);
	MacAddrSimulation * lookup_macaddr(const uint8_t *macaddr);
	MacAddrSimulation * lookup_macaddr_str(const char *charaddr);
	int read_password_signature(const char *filename);

	void simulate_signatures(int num_elemtests, int groupid);
	void sort_signatures();

public:
	PasswordSignature(const char *filename);
	PasswordSignature(int num_elemtests, int groupid);
	bool check_password(const char *password);

	int sae_num_elemtests_any_iteration(const uint8_t *addr1,
		const uint8_t *addr2, const uint8_t *password, size_t password_len,
		uint8_t pwd_seed[SHA256_DIGEST_LENGTH], int iteration);

	/**
	 * Return the number of possible remaining passwords
	 */
	int bruteforce(PasswordList *passwords);

	int num_used_elemtests() const;
};

#endif // timingresults_h
