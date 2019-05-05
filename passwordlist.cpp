#include <string.h>
#include <stdexcept>

#include "passwordlist.h"

PasswordFile::PasswordFile(const char *filename)
{
	FILE *fp = fopen(filename, "r");
	char line[256];

	if (fp == NULL)
		throw std::runtime_error("Could not open signature file");

	while (fgets(line, sizeof(line), fp) != NULL) {
		int len = strlen(line);
		if (line[len - 1] == '\n')
			len--;
		passwords.push_back(std::string(line, len));
	}

	printf("Read %d passwords from %s\n", passwords.size(), filename);
	it_next = passwords.begin();

	fclose(fp);
}

const char * PasswordFile::next()
{
	if (it_next == passwords.end())
		return NULL;

	return (*it_next++).c_str();
}

int PasswordFile::size()
{
	return passwords.size();
}



PasswordGenerator::PasswordGenerator(int num_passwords)
{
	this->num_passwords = num_passwords;
	this->curr_password = 0;
}

const char * PasswordGenerator::next()
{
	if (curr_password >= num_passwords)
		return NULL;

	static char buffer[200];
	snprintf(buffer, sizeof(buffer), "password%d", curr_password);

	curr_password++;
	return buffer;
}

int PasswordGenerator::size()
{
	return num_passwords;
}

