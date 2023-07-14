#include "extension.h"
#include "curlmanager.h"
#include "opensslmanager.h"
#include <curl/curl.h>

cURL_SM g_cURL_SM;

SMEXT_LINK(&g_cURL_SM);

extern sp_nativeinfo_t g_cURLNatives[];

HandleType_t g_cURLHandle = 0;
HandleType_t g_cURLFile = 0;
HandleType_t g_WebForm = 0;
HandleType_t g_cURLSlist = 0;

IdentityToken_t *myself_Identity = NULL;


bool cURL_SM::SDK_OnLoad(char *error, size_t maxlength, bool late)
{
	shutdown = false;

	CURLcode code;

	code = curl_global_init(CURL_GLOBAL_ALL);

	if(code)
	{
		smutils->Format(error, maxlength, "%s", curl_easy_strerror(code));
		return false;
	}

	myself_Identity = myself->GetIdentity();

	bool valid = true;

	HandleError err_file, err_handle, err_webform, err_slist;
	g_cURLFile = handlesys->CreateType("cURLFile", this, 0, NULL, NULL, myself_Identity, &err_file);
	g_cURLHandle = handlesys->CreateType("cURLHandle", this, 0, NULL, NULL, myself_Identity, &err_handle);
	g_WebForm = handlesys->CreateType("cURLWebForm", this, 0, NULL, NULL, myself_Identity, &err_webform);
	g_cURLSlist = handlesys->CreateType("cURLSlist", this, 0, NULL, NULL, myself_Identity, &err_slist);
	
	if(g_cURLFile == 0)
	{
		handlesys->RemoveType(g_cURLFile, myself_Identity);
		g_cURLFile = 0;
		snprintf(error, maxlength, "Could not create CURL file type (err: %d)", err_file);
		valid = false;
	}

	if(g_cURLHandle == 0)
	{
		handlesys->RemoveType(g_cURLHandle, myself_Identity);
		g_cURLHandle = 0;
		snprintf(error, maxlength, "Could not create CURL handle type (err: %d)", err_handle);
		valid = false;
	}
	
	if(g_WebForm == 0)
	{
		handlesys->RemoveType(g_WebForm, myself_Identity);
		g_WebForm = 0;
		snprintf(error, maxlength, "Could not create CURL WebForm type (err: %d)", err_webform);
		valid = false;
	}

	if(g_cURLSlist == 0)
	{
		handlesys->RemoveType(g_cURLSlist, myself_Identity);
		g_cURLSlist = 0;
		snprintf(error, maxlength, "Could not create CURL Slist type (err: %d)", err_slist);
		valid = false;
	}

	if(!valid)
		return false;

	sharesys->AddNatives(myself, g_cURLNatives);

	g_cURLManager.SDK_OnLoad();

	g_OpensslManager.SDK_OnLoad();

	return true;
}

void cURL_SM::SDK_OnUnload()
{
	shutdown = true;

	g_cURLManager.SDK_OnUnload();

	g_OpensslManager.SDK_OnUnload();

	curl_global_cleanup();
}

void cURL_SM::SDK_OnAllLoaded()
{
}

bool cURL_SM::QueryRunning(char *error, size_t maxlength)
{
	return true;
}

void cURL_SM::OnHandleDestroy(HandleType_t type, void *object)
{
	if(type == g_cURLHandle)
	{
		g_cURLManager.RemovecURLHandle((cURLHandle *)object);
	} else if(type == g_cURLFile || type == g_WebForm || type == g_cURLSlist) {
		ICloseHelper *pointer = (ICloseHelper *)object;
		if(pointer->TryDelete())
		{
			g_cURLManager.RemoveCloseHelperHandle(pointer);
			pointer->Delete();
		}
	}
}

bool cURL_SM::IsShutdown()
{
	return shutdown;
}


bool ICloseHelper::TryDelete()
{
	if(_handle == NULL || !_handle->running)
	{
		return true;
	} else {
		_marked_delete = true;
		return false;
	}
}

void cURL_OpenFile::Delete()
{
	fclose(pFile);
	delete this;
}

void WebForm::Delete()
{
	curl_formfree(first);
	slist_record.clear();
	delete this;
}

void cURL_slist_pack::Delete()
{
	curl_slist_free_all(chunk); 
	delete this;
}

char *UTIL_ToLowerCase(const char *str)
{
	size_t len = strlen(str);
	char *buffer = new char[len + 1];
	for (size_t i = 0; i < len; i++)
	{
		if (str[i] >= 'A' && str[i] <= 'Z')
			buffer[i] = tolower(str[i]);
		else
			buffer[i] = str[i];
	}
	buffer[len] = '\0';
	return buffer;
}
