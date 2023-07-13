#include "opensslthread.h"


OpensslThread::OpensslThread(void *_data, OpensslThread_Type _type):
type(_type),data(_data)
{
	assert((type > OpensslThread_Type_NOTHING && type < OpensslThread_Type_LAST));
	assert((data != NULL));
}


OpensslThread::~OpensslThread()
{

}

static void openssl_hash_FramAction(void *data)
{
	if(data == NULL)
		return;

	Openssl_Hash_pack *handle = (Openssl_Hash_pack *)data;
	
	IPluginFunction *pFunc = handle->hash_callback;
	assert((pFunc != NULL));
	if(pFunc != NULL)
	{
		pFunc->PushCell(handle->success);
		if(handle->output == NULL)
			pFunc->PushString("");
		else
			pFunc->PushString(handle->output);
		pFunc->PushCell(handle->UserData);
		pFunc->Execute(NULL);
	}
	
	if(handle->output != NULL)
		delete handle->output;
	if(handle->path != NULL)
		delete handle->path;
	delete handle;
}

void OpensslThread::RunFileHash()
{
	Openssl_Hash_pack *handle = (Openssl_Hash_pack *)data;
	handle->success = false;

	assert((handle->path != NULL));

	char realpath[PLATFORM_MAX_PATH];
	g_pSM->BuildPath(Path_Game, realpath, sizeof(realpath), "%s", handle->path);
	FILE *pFile = fopen(realpath, "rb");
	if(!pFile)
		return;

	unsigned char *output = NULL;
	int outlength;

	if(!g_OpensslManager.HashFile(handle->algorithm, pFile, &output, &outlength))
		goto clean;

	assert((output != NULL));
	if(output != NULL)
	{
		handle->output = new char[outlength*2+1];
		int pos = 0;
		for(int i=0; i<outlength; i++)
		{
			sprintf(&handle->output[pos],"%02x",(unsigned char)output[i]);
			pos+=2;
		}
		handle->success = true;
	}

clean:
	if(output != NULL)
		delete output;

	fclose(pFile);
}

void OpensslThread::RunThread(IThreadHandle *pHandle)
{
	if(type == OpensslThread_Type_HASH_FILE)
	{
		RunFileHash();
	}
}

void OpensslThread::OnTerminate(IThreadHandle *pHandle, bool cancel)
{
	if(type == OpensslThread_Type_HASH_FILE)
	{
		smutils->AddFrameAction(openssl_hash_FramAction, data);
	}

	delete this;
}

