#define CURL_NO_OLDIES

#include "curlmanager.h"

#ifdef PLATFORM_LINUX
#include <netinet/in.h>
#endif


cURLManager g_cURLManager;


struct data_t {
	data_t(cURLHandle *_handle,	size_t _bytes, size_t _nmemb):
	handle(_handle), buffer(NULL), bytes(_bytes), nmemb(_nmemb)
	{
	}
	cURLHandle *handle;
	char *buffer;
	size_t bytes;
	size_t nmemb;
	size_t return_value;
};
#include <io.h>
/* Write Function */
static size_t curl_write_function_default(void *ptr, size_t bytes, size_t nmemb, void *stream)
{
	FILE* file = (FILE*)stream;
    // Pretty sure this is for determining if `stream` is actually a FILE* or not.
    // This is really terrible and we should not be doing this since it erases types.
#ifdef WIN32
	if ( _fileno(file) >= 3 )
#else
	if( fileno(file) >= 3 )
#endif
	{
		return fwrite(ptr, bytes, nmemb, file); 
	}
	return (bytes * nmemb);
}

static size_t Call_Write_Function(cURLHandle *handle, const char *buffer, size_t bytes, size_t nmemb)
{
	IPluginFunction *pFunc = handle->callback_Function[cURL_CallBack_WRITE_FUNCTION];
	assert((pFunc != NULL));
	cell_t result = bytes * nmemb;
	if(pFunc != NULL)
	{
		pFunc->PushCell(handle->hndl);
		pFunc->PushStringEx((char *)buffer, nmemb+1, SM_PARAM_STRING_COPY|SM_PARAM_STRING_BINARY, 0);
		pFunc->PushCell(bytes);
		pFunc->PushCell(nmemb);
		pFunc->PushCell(handle->UserData[UserData_Type_Write_Func]);
		pFunc->Execute(&result);
	}
	return result;
}

static void sm_write_function_FrameAction(void *data)
{
	if(data == NULL)
		return;

	data_t *wdata = (data_t*)data;
	wdata->return_value = Call_Write_Function(wdata->handle, wdata->buffer, wdata->bytes, wdata->nmemb);
	wdata->handle->thread->EventSignal();
}

static size_t curl_write_function_SM(void *ptr, size_t bytes, size_t nmemb, void *stream)
{
	cURLHandle *handle = (cURLHandle *)stream;

	size_t ret;
	if(handle->thread == NULL)
	{
		char *buffer = new char[nmemb+1];
		memcpy(buffer,ptr, nmemb);
		buffer[nmemb] = '\0';
		ret = Call_Write_Function(handle, buffer, bytes, nmemb);
		delete [] buffer;
	} else {
		if(g_cURL_SM.IsShutdown())
			return (bytes * nmemb);

		data_t *data = new data_t(handle, bytes, nmemb);
		data->buffer = new char[nmemb+1];
		memcpy(data->buffer,ptr, nmemb);
		data->buffer[nmemb] = '\0';

		smutils->AddFrameAction(sm_write_function_FrameAction, data);
		handle->thread->EventWait();

		ret = data->return_value;
		delete [] data->buffer;
		delete data;

		if(g_cURL_SM.IsShutdown())
			return (bytes * nmemb);
	}

	return ret;
}

/* Read Function */
static size_t Call_Read_Function(cURLHandle *handle, size_t bytes, size_t nmemb)
{
	IPluginFunction *pFunc = handle->callback_Function[cURL_CallBack_READ_FUNCTION];
	assert((pFunc != NULL));
	cell_t result = bytes * nmemb;
	if(pFunc != NULL)
	{
		pFunc->PushCell(handle->hndl);
		pFunc->PushCell(bytes);
		pFunc->PushCell(nmemb);
		pFunc->PushCell(handle->UserData[UserData_Type_Read_Func]);
		pFunc->Execute(&result);
	}
	return result;
}

static void sm_read_function_FrameAction(void *data)
{
	if(data == NULL)
		return;

	data_t *rdata = (data_t*)data;
	rdata->return_value = Call_Read_Function(rdata->handle, rdata->bytes, rdata->nmemb);
	rdata->handle->thread->EventSignal();
}


static size_t curl_read_function_SM(char *ptr, size_t bytes, size_t nmemb, void *stream)
{
	cURLHandle *handle = (cURLHandle *)stream;

	size_t ret = 0;
	if(handle->thread == NULL)
	{
		ret = Call_Read_Function(handle, bytes, nmemb);
	} else {
		if(g_cURL_SM.IsShutdown())
			return 0;

		data_t *data = new data_t(handle, bytes, nmemb);

		smutils->AddFrameAction(sm_read_function_FrameAction, data);
		handle->thread->EventWait();

		ret = data->return_value;
		delete data;

		if(g_cURL_SM.IsShutdown())
			return 0;
	}

	if(ret > 0)
	{
		memcpy(ptr,handle->send_buffer.data(), handle->send_buffer.size());
	}

	return ret;
}

static curl_socket_t curl_opensocket_function(void *clientp, curlsocktype purpose, struct curl_sockaddr *address)
{
	cURLHandle *handle = (cURLHandle *)clientp;
	if(handle->is_udp)
	{
		address->socktype = SOCK_DGRAM;
		address->protocol = IPPROTO_UDP;
		address->family = AF_INET;
	}

	return socket(address->family, address->socktype, address->protocol);
}

void cURLManager::SDK_OnLoad()
{
	curlhandle_list_mutex = threader->MakeMutex();
	shutdown_event = threader->MakeEventSignal();
	closehelper_list_mutex = threader->MakeMutex();

	waiting = false;
}

void cURLManager::SDK_OnUnload()
{
	curlhandle_list_mutex->Lock();
	if(g_cURLThread_List.size() > 0)
	{
		printf("[%s] Waiting %d cURL Threads Terminate...\n",SMEXT_CONF_LOGTAG,g_cURLThread_List.size());		

		SourceHook::List<cURLThread *>::iterator iter = g_cURLThread_List.begin();
		cURLThread *pInfo;
		while (iter != g_cURLThread_List.end())
		{
			pInfo = (*iter);
			if(pInfo->waiting) {
				pInfo->event->Signal();
			}
			iter++;
		}

		curlhandle_list_mutex->Unlock();

		waiting = true;
		shutdown_event->Wait();

		printf("[%s] All cURL Thread Terminated !!!\n",SMEXT_CONF_LOGTAG);
	} else {
		curlhandle_list_mutex->Unlock();
	}

	shutdown_event->DestroyThis();
	curlhandle_list_mutex->DestroyThis();

	shutdown_event = NULL;
	curlhandle_list_mutex = NULL;
	g_cURLThread_List.clear();

	g_CloseHelper_List.clear();
}

void cURLManager::CreatecURLThread(cURLThread *thread)
{
	if(g_cURL_SM.IsShutdown())
	{
		delete thread;
		return;
	}
	curlhandle_list_mutex->Lock();
	g_cURLThread_List.push_back(thread);
	curlhandle_list_mutex->Unlock();

	threader->MakeThread(thread);
}

void cURLManager::RemovecURLThread(cURLThread *thread)
{
	if(g_cURL_SM.IsShutdown())
	{
		RemovecURLHandle(thread->handle);
	}

	curlhandle_list_mutex->Lock();
	g_cURLThread_List.remove(thread);

	if(waiting)
	{
		if(g_cURLThread_List.size() == 0)
		{
			curlhandle_list_mutex->Unlock();
			shutdown_event->Signal();
			return;
		}
	}
	curlhandle_list_mutex->Unlock();
}

void cURLManager::AddCloseHelperHandle(ICloseHelper *helper)
{
	closehelper_list_mutex->Lock();
	if(g_CloseHelper_List.find(helper) == g_CloseHelper_List.end())
	{
		g_CloseHelper_List.push_back(helper);
	}
	closehelper_list_mutex->Unlock();
}

void cURLManager::RemoveCloseHelperHandle(ICloseHelper *helper)
{
	closehelper_list_mutex->Lock();
	g_CloseHelper_List.remove(helper);
	closehelper_list_mutex->Unlock();
}

void cURLManager::RemoveLinkedICloseHelper(cURLHandle *handle)
{
	closehelper_list_mutex->Lock();

	SourceHook::List<ICloseHelper *>::iterator iter;
	ICloseHelper *pInfo;
	for (iter=g_CloseHelper_List.begin(); iter!=g_CloseHelper_List.end(); iter++)
	{
		pInfo = (*iter);
		if(pInfo->_handle == handle)
		{
			pInfo->_handle = NULL;
			if(pInfo->_marked_delete)
			{
				pInfo->Delete();
				iter = g_CloseHelper_List.erase(iter);
			}
		}
	}

	closehelper_list_mutex->Unlock();
}

void cURLManager::RemovecURLHandle(cURLHandle *handle)
{
	if(!handle || handle->running)
		return;
	
	if(handle->thread != NULL)
	{
		handle->thread->handle = NULL;
	}
	curl_easy_cleanup(handle->curl);
	handle->curl = NULL;

	SourceHook::List<cURLOpt_string *>::iterator iter;
	cURLOpt_string *pInfo;
	for (iter=handle->opt_string_list.begin(); iter!=handle->opt_string_list.end(); iter++)
	{
		pInfo = (*iter);
		delete [] pInfo->value;
		delete pInfo;
	}
	handle->opt_string_list.clear();

	SourceHook::List<cURLOpt_int *>::iterator iter2;
	cURLOpt_int*pInfo2;
	for (iter2=handle->opt_int_list.begin(); iter2!=handle->opt_int_list.end(); iter2++)
	{
		pInfo2 = (*iter2);
		delete pInfo2;
	}
	handle->opt_int_list.clear();	

	SourceHook::List<cURLOpt_pointer *>::iterator iter3;
	cURLOpt_pointer *pInfo3;
	for(iter3=handle->opt_pointer_list.begin(); iter3!=handle->opt_pointer_list.end(); iter3++)
	{
		pInfo3 = (*iter3);
		delete pInfo3;
	}
	handle->opt_pointer_list.clear();

	SourceHook::List<cURLOpt_int64 *>::iterator iter4;
	cURLOpt_int64 *pInfo4;
	for(iter4=handle->opt_int64_list.begin(); iter4!=handle->opt_int64_list.end(); iter4++)
	{
		pInfo4 = (*iter4);
		delete pInfo4;
	}
	handle->opt_int64_list.clear();

	handle->send_buffer.clear();

	RemoveLinkedICloseHelper(handle);

	delete handle;
}

bool cURLManager::AddcURLOptionString(cURLHandle *handle, CURLoption opt, char *value)
{
	if(!handle || handle->running || !value)
		return false;

	std::string value_str;

	bool supported = false;
	switch(opt)
	{
		case CURLOPT_URL:
		{
			char *lowercase_value = UTIL_ToLowerCase(value);
			std::string value_str_lower(lowercase_value);
			delete [] lowercase_value;

			if(!value_str_lower.compare(0,6, "udp://"))
			{
				handle->is_udp = true;
				value_str.assign(&value[6]);
			} else {
				value_str = value;
				handle->is_udp = false;
			}
			supported = true;
			break;
		}
		case CURLOPT_PROXY:
		case CURLOPT_PROXYUSERPWD:
		case CURLOPT_RANGE:
		case CURLOPT_USERPWD:
		case CURLOPT_KEYPASSWD:
		case CURLOPT_POSTFIELDS:
		case CURLOPT_REFERER:
		case CURLOPT_FTPPORT:
		case CURLOPT_USERAGENT:
		case CURLOPT_COOKIE:
		//case CURLOPT_ENCODING:
		case CURLOPT_CUSTOMREQUEST:
		//case CURLOPT_WRITEINFO:
		case CURLOPT_INTERFACE:
		case CURLOPT_KRBLEVEL:
		case CURLOPT_SSL_CIPHER_LIST:
		case CURLOPT_SSLCERTTYPE:
		case CURLOPT_SSLKEYTYPE:
		case CURLOPT_SSLENGINE:
		case CURLOPT_FTP_ACCOUNT:
		case CURLOPT_COOKIELIST:
		case CURLOPT_FTP_ALTERNATIVE_TO_USER:
		case CURLOPT_SSH_HOST_PUBLIC_KEY_MD5:
		case CURLOPT_USERNAME:
		case CURLOPT_PASSWORD:
		case CURLOPT_PROXYUSERNAME:
		case CURLOPT_PROXYPASSWORD:
		case CURLOPT_NOPROXY:
		case CURLOPT_SOCKS5_GSSAPI_SERVICE:
		case CURLOPT_MAIL_FROM:
		case CURLOPT_RTSP_SESSION_ID:
		case CURLOPT_RTSP_STREAM_URI:
		case CURLOPT_RTSP_TRANSPORT:
			value_str.assign(value);
			supported = true;
			break;
		case CURLOPT_COOKIEFILE:
		case CURLOPT_COOKIEJAR:
		case CURLOPT_RANDOM_FILE:
		case CURLOPT_EGDSOCKET:
		case CURLOPT_SSLCERT:
		case CURLOPT_SSLKEY:
		case CURLOPT_CAINFO:
		case CURLOPT_CAPATH:
		case CURLOPT_NETRC_FILE:
		case CURLOPT_SSH_PUBLIC_KEYFILE:
		case CURLOPT_SSH_PRIVATE_KEYFILE:
		case CURLOPT_CRLFILE:
		case CURLOPT_ISSUERCERT:
		case CURLOPT_SSH_KNOWNHOSTS:
		{
			char realpath[PLATFORM_MAX_PATH];
			g_pSM->BuildPath(Path_Game, realpath, sizeof(realpath), "%s", value);
			value_str.assign(realpath);
			supported = true;
			break;
		}
	}

	assert((supported != false));
	if(!supported)
		return false;
	
	cURLOpt_string *stringopt = new cURLOpt_string();
	stringopt->opt = opt;
	stringopt->value = new char[value_str.size()+1];
	memset(stringopt->value, 0, value_str.size()+1);
	memcpy(stringopt->value,value_str.c_str(), value_str.size());

	handle->opt_string_list.push_back(stringopt);

	return true;
}

bool cURLManager::AddcURLOptionInt(cURLHandle *handle, CURLoption opt, int value)
{
	if(!handle || handle->running)
		return false;

	bool supported = false;
	switch(opt)
	{
		case CURLOPT_PORT:
		case CURLOPT_NOPROGRESS:
		case CURLOPT_VERBOSE:
		case CURLOPT_PROXYTYPE:
		case CURLOPT_HTTPPROXYTUNNEL:
		case CURLOPT_TIMEOUT:
		case CURLOPT_SSL_VERIFYPEER:
		case CURLOPT_SSL_VERIFYHOST:
		case CURLOPT_UPLOAD:
		case CURLOPT_INFILESIZE:
		case CURLOPT_LOW_SPEED_LIMIT:
		case CURLOPT_LOW_SPEED_TIME:
		case CURLOPT_RESUME_FROM:
		case CURLOPT_CRLF:
		case CURLOPT_SSLVERSION:
		case CURLOPT_TIMECONDITION:
		case CURLOPT_TIMEVALUE:
		case CURLOPT_HEADER:
		case CURLOPT_NOBODY:
		case CURLOPT_FAILONERROR:
		case CURLOPT_POST:
		case CURLOPT_DIRLISTONLY:
		case CURLOPT_APPEND:
		case CURLOPT_NETRC:
		case CURLOPT_FOLLOWLOCATION:
		case CURLOPT_TRANSFERTEXT:
		case CURLOPT_PUT:
		case CURLOPT_AUTOREFERER:
		case CURLOPT_PROXYPORT:
		case CURLOPT_POSTFIELDSIZE:
		case CURLOPT_MAXREDIRS:
		case CURLOPT_FILETIME:
		case CURLOPT_MAXCONNECTS:
		//case CURLOPT_CLOSEPOLICY:
		case CURLOPT_FRESH_CONNECT:
		case CURLOPT_FORBID_REUSE:
		case CURLOPT_CONNECTTIMEOUT:
		case CURLOPT_HTTPGET:
		case CURLOPT_HTTP_VERSION:
		case CURLOPT_FTP_USE_EPSV:
		case CURLOPT_SSLENGINE_DEFAULT:
		case CURLOPT_DNS_USE_GLOBAL_CACHE:
		case CURLOPT_DNS_CACHE_TIMEOUT:
		case CURLOPT_COOKIESESSION:
		case CURLOPT_BUFFERSIZE:
		case CURLOPT_NOSIGNAL:
		case CURLOPT_UNRESTRICTED_AUTH:
		case CURLOPT_FTP_USE_EPRT:
		case CURLOPT_HTTPAUTH:
		case CURLOPT_FTP_CREATE_MISSING_DIRS:
		case CURLOPT_PROXYAUTH:
		//case CURLOPT_FTP_RESPONSE_TIMEOUT:
		case CURLOPT_IPRESOLVE:
		case CURLOPT_MAXFILESIZE:
		case CURLOPT_USE_SSL:
		case CURLOPT_TCP_NODELAY:
		case CURLOPT_FTPSSLAUTH:
		case CURLOPT_IGNORE_CONTENT_LENGTH:
		case CURLOPT_FTP_SKIP_PASV_IP:
		case CURLOPT_FTP_FILEMETHOD:
		case CURLOPT_LOCALPORT:
		case CURLOPT_LOCALPORTRANGE:
		case CURLOPT_CONNECT_ONLY:
		case CURLOPT_SSL_SESSIONID_CACHE:
		case CURLOPT_SSH_AUTH_TYPES:
		case CURLOPT_FTP_SSL_CCC:
		case CURLOPT_TIMEOUT_MS:
		case CURLOPT_CONNECTTIMEOUT_MS:
		case CURLOPT_HTTP_TRANSFER_DECODING:
		case CURLOPT_HTTP_CONTENT_DECODING:
		case CURLOPT_NEW_FILE_PERMS:
		case CURLOPT_NEW_DIRECTORY_PERMS:
		case CURLOPT_POSTREDIR:
		case CURLOPT_PROXY_TRANSFER_MODE:
		case CURLOPT_ADDRESS_SCOPE:
		case CURLOPT_CERTINFO:
		case CURLOPT_TFTP_BLKSIZE:
		case CURLOPT_PROTOCOLS:
		case CURLOPT_REDIR_PROTOCOLS:
		case CURLOPT_FTP_USE_PRET:
		case CURLOPT_RTSP_REQUEST:
		case CURLOPT_RTSP_CLIENT_CSEQ:
		case CURLOPT_RTSP_SERVER_CSEQ:
		case CURLOPT_WILDCARDMATCH:
		case CURLOPT_TRANSFER_ENCODING:
		case CURLOPT_GSSAPI_DELEGATION:
			supported = true;
			break;
	}

	assert((supported != false));
	if(!supported)
		return false;

	cURLOpt_int *intopt = new cURLOpt_int();
	intopt->opt = opt;
	intopt->value = value;

	handle->opt_int_list.push_back(intopt);

	return true;
}

bool cURLManager::AddcURLOptionInt64(cURLHandle *handle, CURLoption opt, long long value)
{
	if(!handle || handle->running)
		return false;

	bool supported = false;
	switch(opt)
	{
		case CURLOPT_INFILESIZE_LARGE:
		case CURLOPT_RESUME_FROM_LARGE:
		case CURLOPT_MAXFILESIZE_LARGE:
		case CURLOPT_POSTFIELDSIZE_LARGE:
		case CURLOPT_MAX_SEND_SPEED_LARGE:
		case CURLOPT_MAX_RECV_SPEED_LARGE:
			supported = true;
			break;
	}

	assert((supported != false));
	if(!supported)
		return false;

	cURLOpt_int64 *int64opt = new cURLOpt_int64();
	int64opt->opt = opt;
	int64opt->value = (curl_off_t)value;

	handle->opt_int64_list.push_back(int64opt);
	return true;
}

bool cURLManager::AddcURLOptionFunction(IPluginContext *pContext, cURLHandle *handle, CURLoption opt, IPluginFunction *pFunction, int value)
{
	if(!handle || handle->running)
		return false;

	cURL_CallBack index = cURL_CallBack_NOTHING;
	switch(opt)
	{
		case CURLOPT_WRITEFUNCTION:
			index = cURL_CallBack_WRITE_FUNCTION;
			handle->UserData[UserData_Type_Write_Func] = value;
			break;
		case CURLOPT_READFUNCTION:
			index = cURL_CallBack_READ_FUNCTION;
			handle->UserData[UserData_Type_Read_Func] = value;
			break;
	}

	if(index == cURL_CallBack_NOTHING)
		return false;

	handle->callback_Function[index] = pFunction;
	return true;
}


bool cURLManager::AddcURLOptionHandle(IPluginContext *pContext, cURLHandle *handle, HandleSecurity *sec, CURLoption opt, Handle_t hndl)
{
	if(!handle || handle->running)
		return false;

	void *pointer = NULL;
	int err = SP_ERROR_NONE;
	ICloseHelper *helper = NULL;

	switch(opt)
	{
		case CURLOPT_WRITEDATA:
		case CURLOPT_HEADERDATA:
		case CURLOPT_READDATA:
		case CURLOPT_STDERR:
		case CURLOPT_INTERLEAVEDATA:
		{
			cURL_OpenFile *openfile = NULL;
			err = handlesys->ReadHandle(hndl, g_cURLFile, sec, (void **)&openfile);
			if(openfile != NULL)
			{
				pointer = openfile->pFile;
				openfile->_handle = handle;
				helper = openfile;
			}
			break;
		}
		case CURLOPT_HTTPPOST:
		{
			WebForm *webform = NULL;
			err = handlesys->ReadHandle(hndl, g_WebForm, sec, (void **)&webform);
			if(webform != NULL) {
				pointer = webform->first;
				webform->_handle = handle;
				helper = webform;

				SourceHook::List<cURL_slist_pack *>::iterator iter;
				cURL_slist_pack *pInfo;
				for(iter=webform->slist_record.begin(); iter!=webform->slist_record.end(); iter++)
				{
					pInfo = (*iter);
					pInfo->_handle = handle;
					AddCloseHelperHandle(pInfo);
				}
			}
			break;
		}
		case CURLOPT_HTTPHEADER:
		case CURLOPT_QUOTE:
		case CURLOPT_POSTQUOTE:
		case CURLOPT_TELNETOPTIONS:
		case CURLOPT_PREQUOTE:
		case CURLOPT_HTTP200ALIASES:
		case CURLOPT_MAIL_RCPT:
		case CURLOPT_RESOLVE:
		{
			cURL_slist_pack *slist = NULL;
			err = handlesys->ReadHandle(hndl, g_cURLSlist, sec, (void **)&slist);
			if(slist != NULL) {
				pointer = slist->chunk;
				slist->_handle = handle;
				helper = slist;
			}
			break;
		}
	}

	if(err != SP_ERROR_NONE)
	{
		pContext->ThrowNativeErrorEx(err, NULL);
		return false;
	}

	assert((pointer != NULL));
	if(pointer == NULL)
		return false;
	
	
	cURLOpt_pointer *pointeropt = new cURLOpt_pointer();
	pointeropt->opt = opt;
	pointeropt->value = pointer;

	handle->opt_pointer_list.push_back(pointeropt);

	AddCloseHelperHandle(helper);
	return true;
}

void cURLManager::LoadcURLOption(cURLHandle *handle)
{
	if(!handle || handle->opt_loaded)
		return;

	handle->opt_loaded = true;
	
    static bool curlSetSSL = false;
    if (!curlSetSSL)
    {
        // use the system ssl certs
        CURLsslset sslset = curl_global_sslset(CURLSSLBACKEND_OPENSSL, NULL, NULL);
        if (sslset != CURLSSLSET_OK)
        {
            smutils->LogError(myself, "curl_global_sslset failed : %i\n", sslset);
            return;
        }
        curlSetSSL = true;
    }


    curl_easy_setopt(handle->curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
    curl_easy_setopt(handle->curl, CURLOPT_ACCEPT_ENCODING, "");

	curl_easy_setopt(handle->curl, CURLOPT_ERRORBUFFER, handle->errorBuffer);

	curl_easy_setopt(handle->curl, CURLOPT_OPENSOCKETFUNCTION, curl_opensocket_function);
	curl_easy_setopt(handle->curl, CURLOPT_OPENSOCKETDATA, handle);

	if(handle->callback_Function[cURL_CallBack_WRITE_FUNCTION] == NULL)
    {
		curl_easy_setopt(handle->curl, CURLOPT_WRITEFUNCTION, curl_write_function_default);
	}
    else
    {
		curl_easy_setopt(handle->curl, CURLOPT_WRITEFUNCTION, curl_write_function_SM);
		curl_easy_setopt(handle->curl, CURLOPT_WRITEDATA, handle);
	}

	if(handle->callback_Function[cURL_CallBack_READ_FUNCTION] != NULL) {
		curl_easy_setopt(handle->curl, CURLOPT_READFUNCTION, curl_read_function_SM);
		curl_easy_setopt(handle->curl, CURLOPT_READDATA, handle);
	}

	
	SourceHook::List<cURLOpt_string *>::iterator iter;
	cURLOpt_string *pInfo;
	for(iter=handle->opt_string_list.begin(); iter!=handle->opt_string_list.end(); iter++)
	{
		pInfo = (*iter);
		if((handle->lasterror = curl_easy_setopt(handle->curl, pInfo->opt, pInfo->value)) != CURLE_OK)
			return;
	}

	SourceHook::List<cURLOpt_int *>::iterator iter2;
	cURLOpt_int *pInfo2;
	for(iter2=handle->opt_int_list.begin(); iter2!=handle->opt_int_list.end(); iter2++)
	{
		pInfo2 = (*iter2);
		if((handle->lasterror = curl_easy_setopt(handle->curl, pInfo2->opt, pInfo2->value)) != CURLE_OK)
			return;
	}

	SourceHook::List<cURLOpt_pointer *>::iterator iter3;
	cURLOpt_pointer *pInfo3;
	for(iter3=handle->opt_pointer_list.begin(); iter3!=handle->opt_pointer_list.end(); iter3++)
	{
		pInfo3 = (*iter3);
		//Not allow use CURLOPT_WRITEDATA, CURLOPT_READDATA, if write/read function set
		if((handle->callback_Function[cURL_CallBack_WRITE_FUNCTION] != NULL && pInfo3->opt == CURLOPT_WRITEDATA)
			|| (handle->callback_Function[cURL_CallBack_READ_FUNCTION] != NULL && pInfo3->opt == CURLOPT_READDATA))
		{
			continue;
		}
		if((handle->lasterror = curl_easy_setopt(handle->curl, pInfo3->opt, pInfo3->value)) != CURLE_OK)
			return;
	}

	SourceHook::List<cURLOpt_int64 *>::iterator iter4;
	cURLOpt_int64 *pInfo4;
	for(iter4=handle->opt_int64_list.begin(); iter4!=handle->opt_int64_list.end(); iter4++)
	{
		pInfo4 = (*iter4);
		if((handle->lasterror = curl_easy_setopt(handle->curl, pInfo4->opt, (curl_off_t)pInfo4->value)) != CURLE_OK)
			return;
	}
}

CURLFORMcode cURLManager::cURLFormAdd(IPluginContext *pContext, const cell_t *params, WebForm *handle)
{
	assert((handle != NULL));
	if(handle == NULL)
		return CURL_FORMADD_INCOMPLETE;

	unsigned int numparams = (unsigned)params[0];
	unsigned int startparam = 2;	
	if(numparams <= 1 || numparams > 22)
		return CURL_FORMADD_INCOMPLETE;

	// there are only 10 available/supported CURLFORM_*
	CURLformoption form_opts[11] = {CURLFORM_NOTHING};

	char *form_data[10];
	memset(form_data, 0, sizeof(form_data));

	cell_t *addr;
	int count = 0;
	int err;
	int value;
	for(unsigned int i=startparam;i<=numparams;i++)
	{
		if((err=pContext->LocalToPhysAddr(params[i], &addr)) != SP_ERROR_NONE)
		{
			pContext->ThrowNativeErrorEx(err, NULL);
			return CURL_FORMADD_INCOMPLETE;
		}
		CURLformoption form_code = (CURLformoption)*addr;
		switch(form_code)
		{
			case CURLFORM_COPYNAME:
			case CURLFORM_COPYCONTENTS:
			case CURLFORM_FILECONTENT:
			case CURLFORM_FILE:
			case CURLFORM_CONTENTTYPE:
			case CURLFORM_FILENAME:				
				if((err=pContext->LocalToString(params[i+1], &form_data[count])) != SP_ERROR_NONE)
				{
					pContext->ThrowNativeErrorEx(err, NULL);
					return CURL_FORMADD_INCOMPLETE;
				}
				if(form_code == CURLFORM_FILE || form_code == CURLFORM_FILECONTENT) // absolute path
				{
					char realpath[PLATFORM_MAX_PATH];
					g_pSM->BuildPath(Path_Game, realpath, sizeof(realpath), "%s", form_data[count]);
				
					form_data[count] = realpath;
				}
				form_opts[count] = form_code;
				count++;
				i++;
				break;
			case CURLFORM_NAMELENGTH:
			case CURLFORM_CONTENTSLENGTH:				
				if((err=pContext->LocalToPhysAddr(params[i+1], &addr)) != SP_ERROR_NONE)
				{
					pContext->ThrowNativeErrorEx(err, NULL);
					return CURL_FORMADD_INCOMPLETE;
				}
				form_opts[count] = form_code;
				value = *addr;
				form_data[count] = (char *)value;
				count++;
				i++;
				break;
			case CURLFORM_CONTENTHEADER:
			{
				if((err=pContext->LocalToPhysAddr(params[i+1], &addr)) != SP_ERROR_NONE)
				{
					pContext->ThrowNativeErrorEx(err, NULL);
					return CURL_FORMADD_INCOMPLETE;
				}				
				cURL_slist_pack *slist;
				HandleError hndl_err;
				HandleSecurity sec(pContext->GetIdentity(), myself_Identity);
				if((hndl_err = handlesys->ReadHandle(*addr, g_cURLSlist, &sec, (void **)&slist)) != HandleError_None)
				{
					pContext->ThrowNativeError("Invalid curl_slist Handle %x (error %d)", params[1], hndl_err);
					return CURL_FORMADD_INCOMPLETE;
				}
				form_opts[count] = form_code;
				form_data[count] = (char *)slist->chunk;
				handle->slist_record.push_back(slist); // when webform add into curlhandle, will add slist handle to close helper
				count++;
				i++;
				break;
			}
			case CURLFORM_END:
				form_opts[count] = CURLFORM_END;
				goto end;
		}
	}

end:
	CURLFORMcode ret = curl_formadd(&handle->first, &handle->last,
		form_opts[0],
		form_data[0],
		form_opts[1],
		form_data[1],
		form_opts[2],
		form_data[2],
		form_opts[3],
		form_data[3],
		form_opts[4],
		form_data[4],
		form_opts[5],
		form_data[5],
		form_opts[6],
		form_data[6],
		form_opts[7],
		form_data[7],
		form_opts[8],
		form_data[8],
		form_opts[9],
		form_data[9],
		form_opts[10]
	);
	return ret;
}


