#ifndef _INCLUDE_SOURCEMOD_EXTENSION_CURLTHREAD_H_
#define _INCLUDE_SOURCEMOD_EXTENSION_CURLTHREAD_H_

#include "extension.h"
#include "curlmanager.h"
#include <curl/curl.h>
#include <condition_variable>
#include <mutex>


class cURLThread :	public IThread
{
	friend class cURLManager;

public:
	cURLThread(cURLHandle *_handle, cURLThread_Type _type);
	~cURLThread();
	cURLHandle *GetHandle();
	cURLThread_Type GetRunType();
	void EventSignal();
	void EventWait();
	bool IsWaiting();
	// Sets the next send & receive action and wakes the thread from the wait
	// it is in. False when it is not waiting.
	bool SignalAction(SendRecv_Act act);
	// Ends the wait of SendRecv_Act_GOTO_WAIT now and for good: the send &
	// receive loop ends at its next step.
	void Abort();
	char *GetReceiveBuffer();
	void SetRecvBufferSize(unsigned int size);
	void SetSenRecvAction(SendRecv_Act act);
	
public:
	void RunThread(IThreadHandle *pHandle);
	void OnTerminate(IThreadHandle *pHandle, bool cancel);

public:
	void RunThread_Perform();
	void RunThread_Send_Recv();

private:
	// Waits until SignalAction() or Abort(). False when aborted.
	bool WaitForAction();

private:
	bool waiting;
	// The wait of SendRecv_Act_GOTO_WAIT. It has its own lock so that an
	// abort cannot be lost between the check and the wait.
	std::mutex action_mutex;
	std::condition_variable action_cv;
	bool action_waiting;
	bool action_signaled;
	bool aborted;
	cURLHandle *handle;
	cURLThread_Type type;
	IEventSignal *event;
	char *recv_buffer;
	unsigned int recv_buffer_size;
	unsigned int _current_recv_buffer_size;
	SendRecv_Act send_recv_act;

public:
	size_t last_iolen;
};


#endif

