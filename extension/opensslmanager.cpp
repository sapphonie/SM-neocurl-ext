#include "opensslmanager.h"
#include <openssl/crypto.h>
#include <openssl/md5.h>
#include <openssl/md4.h>
#include <openssl/md2.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

// NEED to convert this to using EVP one of these days...
// https://www.openssl.org/docs/manmaster/man3/EVP_DigestInit.html
// -sappho

#define	MD5_FILE_BUFFER_SIZE		1024*16
#define	MD4_FILE_BUFFER_SIZE		1024*16
// #define MD2_FILE_BUFFER_SIZE		1024*16
// #define SHA_FILE_BUFFER_SIZE		1024*16
#define SHA1_FILE_BUFFER_SIZE		1024*16
#define SHA224_FILE_BUFFER_SIZE		1024*16
#define SHA256_FILE_BUFFER_SIZE		1024*16
#define SHA384_FILE_BUFFER_SIZE		1024*16
#define SHA512_FILE_BUFFER_SIZE		1024*16
#define RIPEMD160_FILE_BUFFER_SIZE	1024*16


OpensslManager g_OpensslManager;

static IMutex **ssl_lockarray;

static void MD5_File(FILE *file, unsigned char **output, int *outlength)
{
	*output = new unsigned char[MD5_DIGEST_LENGTH];
	*outlength = MD5_DIGEST_LENGTH;

	MD5_CTX c;
	int i;
	unsigned char buf[MD5_FILE_BUFFER_SIZE];
	
	MD5_Init(&c);
	for (;;)
	{
		i = fread(buf,1,MD5_FILE_BUFFER_SIZE,file);
		if(i <= 0)
			break;
		MD5_Update(&c,buf,(unsigned long)i);
	}
	MD5_Final(*output, &c);
}

static void MD4_File(FILE *file, unsigned char **output, int *outlength)
{
	*output = new unsigned char[MD4_DIGEST_LENGTH];
	*outlength = MD4_DIGEST_LENGTH;

	MD4_CTX c;
	int i;
	unsigned char buf[MD4_FILE_BUFFER_SIZE];
	
	MD4_Init(&c);
	for (;;)
	{
		i = fread(buf,1,MD4_FILE_BUFFER_SIZE,file);
		if(i <= 0)
			break;
		MD4_Update(&c,buf,(unsigned long)i);
	}
	MD4_Final(*output, &c);
}

/*
static void MD2_File(FILE *file, unsigned char **output, int *outlength)
{
	*output = new unsigned char[MD2_DIGEST_LENGTH];
	*outlength = MD2_DIGEST_LENGTH;

	MD2_CTX c;
	int i;
	unsigned char buf[MD2_FILE_BUFFER_SIZE];
	
	MD2_Init(&c);
	for (;;)
	{
		i = fread(buf,1,MD2_FILE_BUFFER_SIZE,file);
		if(i <= 0)
			break;
		MD2_Update(&c,buf,(unsigned long)i);
	}
	MD2_Final(*output, &c);
}

static void SHA_File(FILE *file, unsigned char **output, int *outlength)
{
	*output = new unsigned char[SHA_DIGEST_LENGTH];
	*outlength = SHA_DIGEST_LENGTH;

	SHA_CTX c;
	int i;
	unsigned char buf[SHA_FILE_BUFFER_SIZE];
	
	SHA_Init(&c);
	for (;;)
	{
		i = fread(buf,1,SHA_FILE_BUFFER_SIZE,file);
		if(i <= 0)
			break;
		SHA_Update(&c,buf,(unsigned long)i);
	}
	SHA_Final(*output, &c);
}
*/

static void SHA1_File(FILE *file, unsigned char **output, int *outlength)
{
	*output = new unsigned char[SHA_DIGEST_LENGTH];
	*outlength = SHA_DIGEST_LENGTH;

	SHA_CTX c;
	int i;
	unsigned char buf[SHA1_FILE_BUFFER_SIZE];
	
	SHA1_Init(&c);
	for (;;)
	{
		i = fread(buf,1,SHA1_FILE_BUFFER_SIZE,file);
		if(i <= 0)
			break;
		SHA1_Update(&c,buf,(unsigned long)i);
	}
	SHA1_Final(*output, &c);
}

static void SHA224_File(FILE *file, unsigned char **output, int *outlength)
{
	*output = new unsigned char[SHA224_DIGEST_LENGTH];
	*outlength = SHA224_DIGEST_LENGTH;

	SHA256_CTX c;
	int i;
	unsigned char buf[SHA224_FILE_BUFFER_SIZE];
	
	SHA224_Init(&c);
	for (;;)
	{
		i = fread(buf,1,SHA224_FILE_BUFFER_SIZE,file);
		if(i <= 0)
			break;
		SHA224_Update(&c,buf,(unsigned long)i);
	}
	SHA224_Final(*output, &c);
}

static void SHA256_File(FILE *file, unsigned char **output, int *outlength)
{
	*output = new unsigned char[SHA256_DIGEST_LENGTH];
	*outlength = SHA256_DIGEST_LENGTH;

	SHA256_CTX c;
	int i;
	unsigned char buf[SHA256_FILE_BUFFER_SIZE];
	
	SHA256_Init(&c);
	for (;;)
	{
		i = fread(buf,1,SHA256_FILE_BUFFER_SIZE,file);
		if(i <= 0)
			break;
		SHA256_Update(&c,buf,(unsigned long)i);
	}
	SHA256_Final(*output, &c);
}

static void SHA384_File(FILE *file, unsigned char **output, int *outlength)
{
	*output = new unsigned char[SHA384_DIGEST_LENGTH];
	*outlength = SHA384_DIGEST_LENGTH;

	SHA512_CTX c;
	int i;
	unsigned char buf[SHA384_FILE_BUFFER_SIZE];
	
	SHA384_Init(&c);
	for (;;)
	{
		i = fread(buf,1,SHA384_FILE_BUFFER_SIZE,file);
		if(i <= 0)
			break;
		SHA384_Update(&c,buf,(unsigned long)i);
	}
	SHA384_Final(*output, &c);
}

static void SHA512_File(FILE *file, unsigned char **output, int *outlength)
{
	*output = new unsigned char[SHA512_DIGEST_LENGTH];
	*outlength = SHA512_DIGEST_LENGTH;

	SHA512_CTX c;
	int i;
	unsigned char buf[SHA384_FILE_BUFFER_SIZE];
	
	SHA512_Init(&c);
	for (;;)
	{
		i = fread(buf,1,SHA512_FILE_BUFFER_SIZE,file);
		if(i <= 0)
			break;
		SHA512_Update(&c,buf,(unsigned long)i);
	}
	SHA512_Final(*output, &c);
}

static void RIPEMD160_File(FILE *file, unsigned char **output, int *outlength)
{
	*output = new unsigned char[RIPEMD160_DIGEST_LENGTH];
	*outlength = RIPEMD160_DIGEST_LENGTH;

	RIPEMD160_CTX c;
	int i;
	unsigned char buf[RIPEMD160_FILE_BUFFER_SIZE];
	
	RIPEMD160_Init(&c);
	for (;;)
	{
		i = fread(buf,1,RIPEMD160_FILE_BUFFER_SIZE,file);
		if(i <= 0)
			break;
		RIPEMD160_Update(&c,buf,(unsigned long)i);
	}
	RIPEMD160_Final(*output, &c);
}

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


bool OpensslManager::HashFile(Openssl_Hash algorithm, FILE *pFile, unsigned char **output, int *outlength)
{
	if(pFile == NULL)
		return false;

	switch(algorithm)
	{
		case Openssl_Hash_MD5:
			MD5_File(pFile, output, outlength);
			return true;
		case Openssl_Hash_MD4:
			MD4_File(pFile, output, outlength);
			return true;
		case Openssl_Hash_MD2:
			//MD2_File(pFile, output, outlength);
			//return true;
			return false;
		case Openssl_Hash_SHA:
			//SHA_File(pFile, output, outlength);
			//return true;
			return false;
		case Openssl_Hash_SHA1:
			SHA1_File(pFile, output, outlength);
			return true;
		case Openssl_Hash_SHA224:
			SHA224_File(pFile, output, outlength);
			return true;
		case Openssl_Hash_SHA256:
			SHA256_File(pFile, output, outlength);
			return true;
		case Openssl_Hash_SHA384:
			SHA384_File(pFile, output, outlength);
			return true;
		case Openssl_Hash_SHA512:
			SHA512_File(pFile, output, outlength);
			return true;
		case Openssl_Hash_RIPEMD160:
			RIPEMD160_File(pFile, output, outlength);
			return true;
	}

	return false;
}


bool OpensslManager::HashString(Openssl_Hash algorithm, unsigned char *input, int size, unsigned char *output, int *outlength)
{
	switch(algorithm)
	{
		case Openssl_Hash_MD5:
			MD5(input, size, output);
			*outlength = MD5_DIGEST_LENGTH;
			return true;
		case Openssl_Hash_MD4:
			MD4(input, size, output);
			*outlength = MD4_DIGEST_LENGTH;
			return true;
		//case Openssl_Hash_MD2:
		//	MD2(input, size, output);
		//	*outlength = MD2_DIGEST_LENGTH;
		//	return true;
			return false;
		//case Openssl_Hash_SHA:
		//	SHA(input, size, output);
		//	*outlength = SHA_DIGEST_LENGTH;
		//	return true;
			return false;
		case Openssl_Hash_SHA1:
			SHA1(input, size, output);
			*outlength = SHA_DIGEST_LENGTH;
			return true;
		case Openssl_Hash_SHA224:
			SHA224(input, size, output);
			*outlength = SHA224_DIGEST_LENGTH;
			return true;
		case Openssl_Hash_SHA256:
			SHA256(input, size, output);
			*outlength = SHA256_DIGEST_LENGTH;
			return true;
		case Openssl_Hash_SHA384:
			SHA384(input, size, output);
			*outlength = SHA384_DIGEST_LENGTH;
			return true;
		case Openssl_Hash_SHA512:
			SHA512(input, size, output);
			*outlength = SHA512_DIGEST_LENGTH;
			return true;
		case Openssl_Hash_RIPEMD160:
			RIPEMD160(input, size, output);
			*outlength = RIPEMD160_DIGEST_LENGTH;
			return true;
	}

	return false;
}

