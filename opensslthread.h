#ifndef _INCLUDE_SOURCEMOD_EXTENSION_OPENSSLTHREAD_H_
#define _INCLUDE_SOURCEMOD_EXTENSION_OPENSSLTHREAD_H_

#include "extension.h"
#include "opensslmanager.h"

class OpensslThread : public IThread
{
	friend class OpensslManager;

public:
	OpensslThread(void *_data, OpensslThread_Type type);
	~OpensslThread();

public:
	void RunThread(IThreadHandle *pHandle);
	void OnTerminate(IThreadHandle *pHandle, bool cancel);

private:
	void RunFileHash();

private:
	OpensslThread_Type type;
	void *data;
};


#endif

