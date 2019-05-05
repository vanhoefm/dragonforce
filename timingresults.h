#ifndef timingresults_h
#define timingresults_h

#include <string>
#include <vector>
#include <map>

#include "passwordlist.h"

class PasswordSignature;
class MacAddrSimulation;
class PwFilter;

class PasswordSignature {
public:
	// General info
	const struct ec_group *ec;
	uint8_t bssid[6];
	int group;

	// Current password being checked
	const char *password;
	uint8_t pwd_seed[512];

private:
	// Only used during parsing
	std::map<std::string, MacAddrSimulation*> macaddr_map;
	std::vector<PwFilter*> filters;

	bool parse_macaddr(const char *charaddr, uint8_t *macaddr);
	MacAddrSimulation * lookup_macaddr(const char *charaddr);
	int read_password_signature(const char *filename);

public:
	PasswordSignature(const char *filename);
	bool check_password(const char *password);

	/**
	 * Return the number of possible remaining passwords
	 */
	int bruteforce(PasswordList *passwords);
};

#endif // timingresults_h
