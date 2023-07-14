#include <stdlib.h>
#include "extension.h"
#include "curlmanager.h"
#include "opensslmanager.h"
#include <sh_string.h>
#include <curl/curl.h>

#define SETUP_CURL_HANDLE()\
	cURLHandle *handle;\
	HandleError err;\
	HandleSecurity sec(pContext->GetIdentity(), myself_Identity);\
	if((err = handlesys->ReadHandle(params[1], g_cURLHandle, &sec, (void **)&handle)) != HandleError_None)\
	{\
		return pContext->ThrowNativeError("Invalid Handle %x (error %d)", params[1], err);\
	}

#define SETUP_CURL_WEBFORM()\
	WebForm *handle;\
	HandleError err;\
	HandleSecurity sec(pContext->GetIdentity(), myself_Identity);\
	if((err = handlesys->ReadHandle(params[1], g_WebForm, &sec, (void **)&handle)) != HandleError_None)\
	{\
		return pContext->ThrowNativeError("Invalid Handle %x (error %d)", params[1], err);\
	}

#define SETUP_CURL_SLIST()\
	cURL_slist_pack *handle;\
	HandleError err;\
	HandleSecurity sec(pContext->GetIdentity(), myself_Identity);\
	if((err = handlesys->ReadHandle(params[1], g_cURLSlist, &sec, (void **)&handle)) != HandleError_None)\
	{\
		return pContext->ThrowNativeError("Invalid Handle %x (error %d)", params[1], err);\
	}


static cell_t sm_curl_easy_init(IPluginContext *pContext, const cell_t *params)
{
	CURL *curl = curl_easy_init();
	if(curl == NULL)
	{
		return BAD_HANDLE;
	}

	cURLHandle *handle = new cURLHandle();
	memset(handle->errorBuffer,0,sizeof(handle->errorBuffer));
	memset(handle->callback_Function, 0, sizeof(handle->callback_Function));
	memset(handle->UserData,0,sizeof(handle->UserData));
	handle->curl = curl;

	Handle_t hndl = handlesys->CreateHandle(g_cURLHandle, handle, pContext->GetIdentity(), myself_Identity, NULL);
	if(!hndl)
	{
		curl_easy_cleanup(handle->curl);
		delete handle;
		return BAD_HANDLE;
	}

	handle->hndl = hndl;
	return hndl;
}

static cell_t sm_curl_easy_setopt_string(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	char *buffer;
	pContext->LocalToString(params[3], &buffer);

	return g_cURLManager.AddcURLOptionString(handle, (CURLoption)params[2], buffer);
}

static cell_t sm_curl_easy_setopt_int(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	return g_cURLManager.AddcURLOptionInt(handle, (CURLoption)params[2], params[3]);
}

static cell_t sm_curl_easy_setopt_int_array(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	cell_t *array;
	cell_t array_size = params[3];
	pContext->LocalToPhysAddr(params[2], &array);

	bool valid = true;
	for(int i=0; i<array_size; i++)
	{
		cell_t c1_addr = params[2] + (i * sizeof(cell_t)) + array[i];
		cell_t *c1_r;
		pContext->LocalToPhysAddr(c1_addr, &c1_r);

		bool ret = g_cURLManager.AddcURLOptionInt(handle, (CURLoption)c1_r[0], c1_r[1]);
		if(!ret)
		{
			valid = false;
		}
	}
	return valid;
}

static cell_t sm_curl_easy_setopt_int64(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	char *buffer;
	pContext->LocalToString(params[3], &buffer);

#ifdef WIN32
	long long int value = _atoi64(buffer);
#else
	long long int value = atoll(buffer);
#endif
	return g_cURLManager.AddcURLOptionInt64(handle, (CURLoption)params[2], value);
}

static cell_t sm_curl_easy_setopt_handle(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	return g_cURLManager.AddcURLOptionHandle(pContext, handle, &sec, (CURLoption)params[2], params[3]);
}

static cell_t sm_curl_easy_setopt_function(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	IPluginFunction *pFunction = pContext->GetFunctionById(params[3]);
	if(!pFunction)
	{
		return pContext->ThrowNativeError("Invalid function %x", params[3]);
	}

	return g_cURLManager.AddcURLOptionFunction(pContext, handle, (CURLoption)params[2], pFunction, params[4]);
}

static cell_t sm_curl_easy_perform_thread(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	IPluginFunction *pFunction = pContext->GetFunctionById(params[2]);
	if(!pFunction)
	{
		return pContext->ThrowNativeError("Invalid function %x", params[2]);
	}

	handle->UserData[UserData_Type_Complete] = params[3];	
	handle->callback_Function[cURL_CallBack_COMPLETE] = pFunction;
	cURLThread *thread = new cURLThread(handle, cURLThread_Type_PERFORM);
	g_cURLManager.CreatecURLThread(thread);

	return 1;
}

static cell_t sm_curl_easy_perform(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();
	
	handle->running = true;
	CURLcode code = curl_easy_perform(handle->curl);
	handle->running = false;
	curl_easy_getinfo(handle->curl, CURLINFO_LASTSOCKET, &handle->sockextr);

	return code;
}

static cell_t sm_curl_easy_getinfo_string(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();
	
	int type = (CURLINFO_TYPEMASK & (int)params[2]);

	CURLcode code = CURLE_BAD_FUNCTION_ARGUMENT;
	if(type == CURLINFO_STRING)
	{
		char *string_buffer;
		code = curl_easy_getinfo(handle->curl, (CURLINFO)params[2], &string_buffer);
		if(code == CURLE_OK)
		{
			pContext->StringToLocalUTF8(params[3], params[4], string_buffer, NULL);
		}
	}

	return code;
}

static cell_t sm_curl_easy_getinfo_int(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	int type = (CURLINFO_TYPEMASK & (int)params[2]);

	cell_t *addr;
	pContext->LocalToPhysAddr(params[3], &addr);
	CURLcode code = CURLE_BAD_FUNCTION_ARGUMENT;

	switch(type)
	{
		case CURLINFO_LONG:
			long long_buffer;
			code = curl_easy_getinfo(handle->curl, (CURLINFO)params[2], &long_buffer);
			if(code == CURLE_OK)
			{
				*addr = (cell_t)long_buffer;
			}
			break;
		case CURLINFO_DOUBLE:
			double double_buffer;
			code = curl_easy_getinfo(handle->curl, (CURLINFO)params[2], &double_buffer);
			if(code == CURLE_OK)
			{
				*addr = sp_ftoc((float)double_buffer);
			}
			break;
	}
	return code;
}

static cell_t sm_curl_load_opt(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();
	
	g_cURLManager.LoadcURLOption(handle);
	return handle->lasterror;
}

static cell_t sm_curl_get_error_buffer(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();
	
	pContext->StringToLocalUTF8(params[2], params[3], handle->errorBuffer, NULL);
	return 1;
}

static cell_t sm_curl_easy_escape(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	char *url;
	pContext->LocalToString(params[2], &url);

	char *buffer = curl_easy_escape(handle->curl, url, strlen(url));
	if(buffer == NULL)
		return 0;

	pContext->StringToLocalUTF8(params[3], params[4], buffer, NULL);
	curl_free(buffer);
	return 1;
}

static cell_t sm_curl_easy_unescape(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	char *url;
	pContext->LocalToString(params[2], &url);

	int outlen;
	char *buffer = curl_easy_unescape(handle->curl, url, strlen(url), &outlen);
	if(buffer == NULL)
		return 0;

	pContext->StringToLocalUTF8(params[3], params[4], buffer, NULL);
	curl_free(buffer);
	return outlen;
}

static cell_t sm_curl_easy_strerror(IPluginContext *pContext, const cell_t *params)
{
	const char *error_code = curl_easy_strerror((CURLcode)params[1]);
	pContext->StringToLocalUTF8(params[2], params[3], error_code, NULL);
	return 1;
}

/* send & recv */
static cell_t sm_curl_easy_send_recv(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	IPluginFunction *pFunction_send = pContext->GetFunctionById(params[2]);
	if(!pFunction_send)
	{
		return pContext->ThrowNativeError("Invalid function %x", params[2]);
	}
	
	IPluginFunction *pFunction_recv = pContext->GetFunctionById(params[3]);
	if(!pFunction_recv)
	{
		return pContext->ThrowNativeError("Invalid function %x", params[3]);
	}

	IPluginFunction *pFunction_complete = pContext->GetFunctionById(params[4]);
	if(!pFunction_complete)
	{
		return pContext->ThrowNativeError("Invalid function %x", params[4]);
	}

	handle->send_timeout = params[6];
	handle->recv_timeout = params[7];
	handle->UserData[UserData_Type_Send_Recv] = params[9];
	handle->callback_Function[cURL_CallBack_SEND] = pFunction_send;
	handle->callback_Function[cURL_CallBack_RECV] = pFunction_recv;
	handle->callback_Function[cURL_CallBack_COMPLETE] = pFunction_complete;
	cURLThread *thread = new cURLThread(handle, cURLThread_Type_SEND_RECV);
	thread->SetRecvBufferSize(params[8]);
	thread->SetSenRecvAction((SendRecv_Act)params[5]);
	g_cURLManager.CreatecURLThread(thread);

	return 1;
}

static cell_t sm_curl_send_recv_Signal(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	if(handle->thread == NULL)
		return 0;

	cURLThread *thread = handle->thread;
	if(thread->GetRunType() != cURLThread_Type_SEND_RECV ||
		!handle->running || !thread->IsWaiting()) // is send & recv thread, running, is waiting 
	{
		return 0;
	}

	thread->SetSenRecvAction((SendRecv_Act)params[2]);
	thread->EventSignal();

	return 1;
}


static cell_t sm_curl_send_recv_IsWaiting(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	cURLThread *thread = handle->thread;
	if(thread == NULL || thread->GetRunType() != cURLThread_Type_SEND_RECV || !handle->running)
		return 0;

	return (thread->IsWaiting()) ? 1 : 0;
}


static cell_t sm_curl_set_send_buffer(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	char *buffer;
	pContext->LocalToString(params[2], &buffer);

	if(params[3] == -1)
	{
		handle->send_buffer.assign(buffer);
	} else {		
		handle->send_buffer.assign(buffer,params[3]);
	}

	return 1;
}

static cell_t sm_curl_set_receive_size(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	if(handle->thread != NULL)
	{
		handle->thread->SetRecvBufferSize((unsigned int)params[2]);
	}
	return 1;
}

static cell_t sm_curl_set_send_timeout(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	if(params[2] > 0)
		handle->send_timeout = params[2];

	return 1;
}

static cell_t sm_curl_set_recv_timeout(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	if(params[2] > 0)
		handle->recv_timeout = params[2];

	return 1;
}

/* Stuff */
static cell_t sm_curl_version(IPluginContext *pContext, const cell_t *params)
{
	pContext->StringToLocalUTF8(params[1], params[2], curl_version(), NULL);
	return 1;
}

static cell_t sm_curl_features(IPluginContext *pContext, const cell_t *params)
{
	curl_version_info_data *vinfo = curl_version_info(CURLVERSION_NOW);
	return vinfo->features;
}

static cell_t sm_curl_protocols(IPluginContext *pContext, const cell_t *params)
{
	curl_version_info_data *vinfo = curl_version_info(CURLVERSION_NOW);

	SourceHook::String buffer;
	const char * const *proto;
	for(proto=vinfo->protocols; *proto; ++proto) {
		buffer.append(*proto);
		buffer.append(" ");
    }
	buffer.trim();
	pContext->StringToLocalUTF8(params[1], params[2], buffer.c_str(), NULL);
	return 1;
}

static cell_t sm_curl_OpenFile(IPluginContext *pContext, const cell_t *params)
{
	char *name, *mode;
	int err;
	if ((err=pContext->LocalToString(params[1], &name)) != SP_ERROR_NONE)
	{
		pContext->ThrowNativeErrorEx(err, NULL);
		return 0;
	}
	if ((err=pContext->LocalToString(params[2], &mode)) != SP_ERROR_NONE)
	{
		pContext->ThrowNativeErrorEx(err, NULL);
		return 0;
	}

	char realpath[PLATFORM_MAX_PATH];
	g_pSM->BuildPath(Path_Game, realpath, sizeof(realpath), "%s", name);

	FILE *pFile = fopen(realpath, mode);
	if(!pFile)
		return 0;	

	cURL_OpenFile *openfile = new cURL_OpenFile();
	openfile->pFile = pFile;

	return handlesys->CreateHandle(g_cURLFile, openfile, pContext->GetIdentity(), myself_Identity, NULL);
}

static cell_t sm_curl_httppost(IPluginContext *pContext, const cell_t *params)
{
	WebForm *webform = new WebForm();

	Handle_t hndl = handlesys->CreateHandle(g_WebForm, webform, pContext->GetIdentity(), myself_Identity, NULL);
	if(!hndl)
	{
		delete webform;
		return BAD_HANDLE;
	}
	return hndl;
}

static cell_t sm_curl_formadd(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_WEBFORM();

	return (cell_t)g_cURLManager.cURLFormAdd(pContext, params, handle);
}

static cell_t sm_curl_slist_append(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_SLIST();
	
	char *data;
	pContext->LocalToString(params[2], &data);

	handle->chunk = curl_slist_append(handle->chunk, data);
	return 1;
}

static cell_t sm_curl_slist(IPluginContext *pContext, const cell_t *params)
{
	cURL_slist_pack *slist_pack = new cURL_slist_pack();

	Handle_t hndl = handlesys->CreateHandle(g_cURLSlist, slist_pack, pContext->GetIdentity(), myself_Identity, NULL);
	if(!hndl)
	{
		delete slist_pack;
		return BAD_HANDLE;
	}
	return hndl;
}

static cell_t sm_curl_hash_file(IPluginContext *pContext, const cell_t *params)
{
	IPluginFunction *pFunction = pContext->GetFunctionById(params[3]);
	if(!pFunction)
	{
		return pContext->ThrowNativeError("Invalid function %x", params[3]);
	}

	char *filepath;
	pContext->LocalToString(params[1], &filepath);
	int len = strlen(filepath);

	Openssl_Hash_pack *hash_pack = new Openssl_Hash_pack();
	hash_pack->UserData = params[4];
	hash_pack->path = new char[len+1];
	strncpy(hash_pack->path, filepath, len);
	hash_pack->path[len] = '\0';

	hash_pack->hash_callback = pFunction;
	hash_pack->algorithm = (Openssl_Hash)params[2];

	OpensslThread *thread =  new OpensslThread(hash_pack, OpensslThread_Type_HASH_FILE);
	threader->MakeThread(thread);
	
	return 1;
}

static cell_t sm_curl_hash_string(IPluginContext *pContext, const cell_t *params)
{
	Openssl_Hash hashType = (Openssl_Hash)params[3];
	if
	(
		   hashType == Openssl_Hash_MD2
		|| hashType == Openssl_Hash_SHA
	)
	{
		return pContext->ThrowNativeError("Deprecated hash function %x - Sorry!", params[3]);
	}

	char *input;
	unsigned int data_size = (unsigned int)params[2];
	if(data_size > 0)
	{
		cell_t *addr;
		pContext->LocalToPhysAddr(params[1], &addr);
		input = (char *)addr;
		data_size = params[2];		
	} else {		
		pContext->LocalToString(params[1], &input);
		data_size = strlen(input);
	}

	unsigned char output[128];
	int outlength = 0;
	bool ret = g_OpensslManager.HashString((Openssl_Hash)params[3], (unsigned char *)input, data_size, &output[0], &outlength);
	if(!ret || outlength == 0)
		return 0;

	char buffer[256];
	int pos = 0;
	for(int i=0; i<outlength; i++)
	{
		sprintf(&buffer[pos],"%02x",(unsigned char)output[i]);
		pos+=2;
	}
	size_t bytes;
	pContext->StringToLocalUTF8(params[4], params[5], buffer, &bytes);
	return 1;
}

sp_nativeinfo_t g_cURLNatives[] = 
{ 
	{"curl_easy_init",				sm_curl_easy_init},
	{"curl_easy_setopt_string",		sm_curl_easy_setopt_string},
	{"curl_easy_setopt_int",		sm_curl_easy_setopt_int},
	{"curl_easy_setopt_int_array",	sm_curl_easy_setopt_int_array},
	{"curl_easy_setopt_int64",		sm_curl_easy_setopt_int64},
	{"curl_easy_setopt_handle",		sm_curl_easy_setopt_handle},
	{"curl_easy_setopt_function",	sm_curl_easy_setopt_function},
	{"curl_easy_perform_thread",	sm_curl_easy_perform_thread},
	{"curl_easy_perform",			sm_curl_easy_perform},
	{"curl_easy_getinfo_string",	sm_curl_easy_getinfo_string},
	{"curl_easy_getinfo_int",		sm_curl_easy_getinfo_int},
	{"curl_load_opt",				sm_curl_load_opt},
	{"curl_easy_escape",			sm_curl_easy_escape},
	{"curl_easy_unescape",			sm_curl_easy_unescape},
	{"curl_easy_strerror",			sm_curl_easy_strerror},
	{"curl_get_error_buffer",		sm_curl_get_error_buffer},

	{"curl_easy_send_recv",			sm_curl_easy_send_recv},
	{"curl_set_send_buffer",		sm_curl_set_send_buffer},
	{"curl_send_recv_Signal",		sm_curl_send_recv_Signal},
	{"curl_send_recv_IsWaiting",	sm_curl_send_recv_IsWaiting},
	{"curl_set_receive_size",		sm_curl_set_receive_size},
	{"curl_set_send_timeout",		sm_curl_set_send_timeout},
	{"curl_set_recv_timeout",		sm_curl_set_recv_timeout},

	{"curl_version",				sm_curl_version},
	{"curl_features",				sm_curl_features},
	{"curl_protocols",				sm_curl_protocols},
	{"curl_OpenFile",				sm_curl_OpenFile},

	{"curl_httppost",				sm_curl_httppost},
	{"curl_formadd",				sm_curl_formadd},

	{"curl_slist_append",			sm_curl_slist_append},
	{"curl_slist",					sm_curl_slist},

	{"curl_hash_file",				sm_curl_hash_file},
	{"curl_hash_string",			sm_curl_hash_string},

	{NULL,							NULL}
};


