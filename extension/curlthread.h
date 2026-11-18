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
	// Has action(data) called in a game frame and waits until that called
	// EventSignal(). Returns early when the extension unloads; the action is
	// not called then. Transfer thread only.
	void CallInFrame(void (*action)(void *), void *data);
	void EventSignal();
	bool IsWaiting();
	// Sets the next send & receive action and wakes the thread from the wait
	// it is in. False when it is not waiting.
	bool SignalAction(SendRecv_Act act);
	// Ends the wait of SendRecv_Act_GOTO_WAIT now and for good: the send &
	// receive loop ends at its next step.
	void Abort();
	// The extension unloads: ends every wait of the thread, now and for good.
	void Stop();
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
	// Waits until the socket can be read or written, at most timeout_ms.
	// False when it cannot by then or the extension unloads.
	bool WaitOnSocket(bool for_recv, long timeout_ms);

private:
	// Guards the flags of both waits, so that a signal cannot be lost
	// between a wait's check and its sleep.
	std::mutex action_mutex;
	std::condition_variable action_cv;
	// The wait of CallInFrame().
	bool waiting;
	bool frame_signaled;
	// The wait of SendRecv_Act_GOTO_WAIT.
	bool action_waiting;
	bool action_signaled;
	bool aborted;
	bool stopped;
	cURLHandle *handle;
	cURLThread_Type type;
	char *recv_buffer;
	unsigned int recv_buffer_size;
	unsigned int _current_recv_buffer_size;
	SendRecv_Act send_recv_act;

public:
	size_t last_iolen;
};


#endif

