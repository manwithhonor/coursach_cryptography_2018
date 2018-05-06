#include "debug.h"
#include <cstring>

#include <new>

void vassert(
	const char *file,
	const int line,
	const char *exp,
	const char *msg)
{
	std::cerr << "ASSERT: " << file << ":" << line << ": " << exp << "\n";
	std::cerr << "MESSAGE: " << msg << std::endl;
	abort();
}