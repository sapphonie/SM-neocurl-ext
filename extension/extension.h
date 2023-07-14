#ifndef _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_
#define _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_

#include "smsdk_ext.h"
#include <string>
#include "define.h"
#include <assert.h>
#include <cstring>

class cURL_SM :
	public SDKExtension,
	public IHandleTypeDispatch
{
public:
	virtual bool SDK_OnLoad(char *error, size_t maxlength, bool late);
	virtual void SDK_OnUnload();
	virtual void SDK_OnAllLoaded();
	virtual bool QueryRunning(char *error, size_t maxlength);

public:
	void OnHandleDestroy(HandleType_t type, void *object);

public:
	bool IsShutdown();

private:
	bool shutdown;

};

extern cURL_SM g_cURL_SM;

extern HandleType_t g_cURLHandle;
extern HandleType_t g_cURLFile;
extern HandleType_t g_WebForm;
extern HandleType_t g_cURLSlist;

extern IdentityToken_t *myself_Identity ;

extern char *UTIL_ToLowerCase(const char *str);

#endif

