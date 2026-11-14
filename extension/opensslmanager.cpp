#include "opensslmanager.h"
#include "core/digest.h"
#include <openssl/crypto.h>

#include <memory>
#include <string>
#include <vector>

/* The deprecated curl_hash_file and curl_hash_string, on the digests of
 * core/digest.h, which Crypt (curl_crypt.inc) uses too. */

#define HASH_FILE_BUFFER_SIZE		1024*16

OpensslManager g_OpensslManager;

static IMutex **ssl_lockarray;

static void ssl_locking_callback(int mode, int type, const char *file, int line)
{
    if(mode & CRYPTO_LOCK)
    {
		ssl_lockarray[type]->Lock();
    } else {
		ssl_lockarray[type]->Unlock();
    }
}

#ifdef PLATFORM_LINUX
static unsigned long ssl_id_function(void)
{
	return ((unsigned long)getpid());
}
#endif

void OpensslManager::SDK_OnLoad()
{
	ssl_lockarray = (IMutex **)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(IMutex *));
	for(int i = 0; i < CRYPTO_num_locks(); i++)
    {
		ssl_lockarray[i] = threader->MakeMutex();
	}

#ifdef PLATFORM_LINUX
	CRYPTO_set_id_callback(ssl_id_function);
#endif
	CRYPTO_set_locking_callback(ssl_locking_callback);
}

void OpensslManager::SDK_OnUnload()
{
#ifdef PLATFORM_LINUX
	CRYPTO_set_id_callback(NULL);
#endif
	CRYPTO_set_locking_callback(NULL);
	for (int i=0; i<CRYPTO_num_locks(); i++)
	{
		ssl_lockarray[i]->DestroyThis();
	} 
	OPENSSL_free(ssl_lockarray);
}


static bool CopyDigest(const std::string &digest, unsigned char *output, int *outlength)
{
	if(digest.empty())
		return false;
	memcpy(output, digest.data(), digest.size());
	*outlength = (int)digest.size();
	return true;
}

bool OpensslManager::HashFile(Openssl_Hash algorithm, FILE *pFile, unsigned char **output, int *outlength)
{
	if(pFile == NULL)
		return false;

	std::unique_ptr<neocurl::Hasher> hasher = neocurl::CreateHasher((neocurl::Algorithm)algorithm, NULL);
	if(!hasher)
		return false;

	std::vector<char> buffer(HASH_FILE_BUFFER_SIZE);
	for(;;)
	{
		size_t length = fread(buffer.data(), 1, buffer.size(), pFile);
		if(ferror(pFile) || !hasher->Update(buffer.data(), length))
			return false;
		if(length < buffer.size())
			break;
	}

	std::string digest = hasher->Finish();
	if(digest.empty())
		return false;
	*output = new unsigned char[digest.size()];
	return CopyDigest(digest, *output, outlength);
}


bool OpensslManager::HashString(Openssl_Hash algorithm, unsigned char *input, int size, unsigned char *output, int *outlength)
{
	std::string digest;
	if(neocurl::DigestBytes((neocurl::Algorithm)algorithm, NULL, input, size, digest) != neocurl::DigestError::None)
		return false;
	return CopyDigest(digest, output, outlength);
}
