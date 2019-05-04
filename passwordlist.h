#ifndef passwordlist_h
#define passwordlist_h

#include <string>
#include <list>

class PasswordList {
public:
	virtual const char * next() = 0;
	virtual int size() = 0;
};

class PasswordFile : public PasswordList {
private:
	std::list<std::string> passwords;
	std::list<std::string>::const_iterator it_next;

public:
	PasswordFile(const char *filename);
	virtual const char * next();
	virtual int size();
};

class PasswordGenerator : public PasswordList {
private:
	int num_passwords;
	int curr_password;

public:
	PasswordGenerator(int num_passwords);
	virtual const char * next();
	virtual int size();
};

#endif // passwordlist_h
