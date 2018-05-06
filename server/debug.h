#ifndef DEBUG_H
#define DEBUG_H

#include <iostream>
#include <cstdlib>

void vassert(
	const char *file,
	const int line,
	const char *exp,
	const char *msg);

#define VASSERT(exp, msg) \
	if (!(exp)) vassert(__FILE__, __LINE__, #exp, msg);
	
#ifdef NDEBUG
#define DASSERT(exp, msg)
#else
#define DASSERT(exp, msg) VASSERT(exp, msg)
#endif

#define ASSERT(exp) DASSERT(exp, "")

#ifdef NDEBUG
#define DEBUG_ONLY(exp)
#else
#define DEBUG_ONLY(exp) exp
#endif

#define GL_CHECK(param) \
	param;\
	VASSERT((glGetError() == GL_NO_ERROR), "OpenGl internal error occured");

#define FT_CHECK(param) VASSERT(!param, "Freetype error occured")
	
#endif