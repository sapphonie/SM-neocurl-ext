#ifndef _INCLUDE_SOURCEMOD_EXTENSION_DEFINE_H_
#define _INCLUDE_SOURCEMOD_EXTENSION_DEFINE_H_

#include <atomic>
#include <sh_list.h>
#include <curl/curl.h>

class cURLThread;
struct cURLHandle;


enum SendRecv_Act {
	SendRecv_Act_NOTHING = 0,

	SendRecv_Act_GOTO_SEND,
	SendRecv_Act_GOTO_RECV,
	SendRecv_Act_GOTO_WAIT,
	SendRecv_Act_GOTO_END,
	SendRecv_Act_GOTO_SEND_NO_WAIT,
	SendRecv_Act_GOTO_RECV_NO_WAIT,

	SendRecv_Act_LAST,
};

enum cURLThread_Type {
	cURLThread_Type_NOTHING = 0,

	cURLThread_Type_PERFORM,
	cURLThread_Type_SEND_RECV,

	cURLThread_Type_LAST,
};

enum cURL_CallBack {
	cURL_CallBack_NOTHING = 0,

	cURL_CallBack_COMPLETE,
	cURL_CallBack_SEND,
	cURL_CallBack_RECV,

	cURL_CallBack_WRITE_FUNCTION,
	cURL_CallBack_READ_FUNCTION,
	cURL_CallBack_PROGRESS_FUNCTION,

	cURL_CallBack_LAST,
};

struct cURLOpt_string {
	CURLoption opt;
	char *value;
};

struct cURLOpt_int {
	CURLoption opt;
	int value;
};

struct cURLOpt_int64 {
	CURLoption opt;
	curl_off_t value;
};

struct cURLOpt_pointer {
	CURLoption opt;
	void *value;
};

enum UserData_Type
{
	UserData_Type_Complete = 0,
	UserData_Type_Send_Recv,
	UserData_Type_Write_Func,
	UserData_Type_Read_Func,
	UserData_Type_Progress_Func,

	UserData_Type_LAST,
};

struct cURLHandle {
	cURLHandle():curl(NULL),running(false),finished(false),destroyed(false),lasterror(CURLE_OK),opt_loaded(false),
		progress_interval_ms(1000),progress_last_ms(0),progress_pending(false),progress_abort(false),
		thread(NULL),is_udp(false),sockextr(CURL_SOCKET_BAD),send_timeout(60000),recv_timeout(60000)
	{
	}
	CURL *curl;
	char errorBuffer[CURL_ERROR_SIZE];
	SourceHook::List<cURLOpt_string *> opt_string_list;
	SourceHook::List<cURLOpt_int *> opt_int_list;
	SourceHook::List<cURLOpt_int64 *> opt_int64_list;
	SourceHook::List<cURLOpt_pointer *> opt_pointer_list;
	bool running;
	// A transfer of the handle ended; its options are not used anymore.
	bool finished;
	// The plugin's Handle was closed (delete, or the plugin unloaded) while
	// a transfer was running. From then on no callback of the plugin is
	// called, the transfer is aborted and whoever ends it frees the handle.
	std::atomic<bool> destroyed;
	CURLcode lasterror;
	bool opt_loaded;
	IPluginFunction *callback_Function[cURL_CallBack_LAST];
	Handle_t hndl;
	int UserData[UserData_Type_LAST];

	/* The plugin's progress callback (CURLOPT_XFERINFOFUNCTION). */
	// The least time between two reports.
	long progress_interval_ms;
	// When the last report was made, on the clock of ProgressClockMs(); read and written by the transfer only.
	long long progress_last_ms;
	// A report waits for its game frame; no second one is queued meanwhile.
	std::atomic<bool> progress_pending;
	// The plugin's callback asked to stop the transfer.
	std::atomic<bool> progress_abort;
	cURLThread *thread;
	bool is_udp;

	/* use for send & recv */
	// The socket of the last connection, in the platform's own type: a
	// Windows socket does not fit into a long on 64-bit.
	curl_socket_t sockextr;
	long send_timeout;
	long recv_timeout;

	std::string send_buffer;
};

class ICloseHelper {
public:
	ICloseHelper():_handle(NULL),_marked_delete(false)
	{
	}
	cURLHandle *_handle;
	bool _marked_delete;
	bool TryDelete();
	virtual void Delete() =0;
};

class cURL_slist_pack : public ICloseHelper {
public:
	cURL_slist_pack():chunk(NULL)
	{
	}
	curl_slist *chunk;
	void Delete();
};

class WebForm : public ICloseHelper {
public:
	WebForm():first(NULL), last(NULL)
	{
	}
	curl_httppost *first;
	curl_httppost *last;
	SourceHook::List<cURL_slist_pack *> slist_record;
	void Delete();
};

class cURL_OpenFile : public ICloseHelper {
public:
	FILE *pFile;
	void Delete();
};


enum OpensslThread_Type {
	OpensslThread_Type_NOTHING = 0,

	OpensslThread_Type_HASH_FILE,

	OpensslThread_Type_LAST,
};

enum Openssl_Hash
{
    Openssl_Hash_MD5 = 0,
    Openssl_Hash_DEPRECATED_MD4_UNUSABLE,
    Openssl_Hash_DEPRECATED_MD2_UNUSABLE,
    Openssl_Hash_DEPRECATED_SHA_UNUSABLE,
    Openssl_Hash_SHA1,
    Openssl_Hash_SHA224,
    Openssl_Hash_SHA256,
    Openssl_Hash_SHA384,
    Openssl_Hash_SHA512,
    Openssl_Hash_DEPRECATED_RIPEMD160_UNUSABLE,
    // The values of neocurl::Algorithm (core/digest.h) from here on.
    Openssl_Hash_SHA512_224,
    Openssl_Hash_SHA512_256,
    Openssl_Hash_SHA3_224,
    Openssl_Hash_SHA3_256,
    Openssl_Hash_SHA3_384,
    Openssl_Hash_SHA3_512,
    Openssl_Hash_BLAKE2B512,
    Openssl_Hash_BLAKE2S256,
    Openssl_Hash_SM3,
    Openssl_Hash_KECCAK256,
    Openssl_Hash_CRC32,
    Openssl_Hash_ADLER32,
};

struct Openssl_Hash_pack {
	Openssl_Hash_pack():path(NULL), output(NULL)
	{
	}
	IPluginFunction *hash_callback;
	int UserData;
	char *path;
	Openssl_Hash algorithm;
	bool success;
	char *output;
};

#endif
