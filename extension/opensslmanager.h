#ifndef _INCLUDE_SOURCEMOD_EXTENSION_OPENSSLMANAGER_H_
#define _INCLUDE_SOURCEMOD_EXTENSION_OPENSSLMANAGER_H_

#include "extension.h"
#include "opensslthread.h"

class OpensslManager
{
public:
	void SDK_OnLoad();
	void SDK_OnUnload();

public:
	bool HashFile(Openssl_Hash algorithm, FILE *pFile, unsigned char **output, int *outlength);
	bool HashString(Openssl_Hash algorithm, unsigned char *input, int size, unsigned char *output, int *outlength);

};

extern OpensslManager g_OpensslManager;


#endif

