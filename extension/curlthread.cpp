#include "curlthread.h"
#include <string.h>

static int wait_on_socket(curl_socket_t sockfd, bool for_recv, long timeout_ms)
{
	struct timeval tv;
	fd_set infd, outfd, errfd;
	int res; 
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec= (timeout_ms % 1000) * 1000;
 
	FD_ZERO(&infd);
	FD_ZERO(&outfd);
	FD_ZERO(&errfd);
 
	FD_SET(sockfd, &errfd); /* always check for error */ 
 
	if(for_recv)
	{
		FD_SET(sockfd, &infd);
	} else {
		FD_SET(sockfd, &outfd);
	} 
	/* select() returns the number of signalled sockets or -1 */ 
	// Windows ignores the first argument; elsewhere a socket is an int.
	res = select(static_cast<int>(sockfd + 1), &infd, &outfd, &errfd, &tv);
	return res;
}


cURLThread::cURLThread(cURLHandle *_handle, cURLThread_Type _type):
waiting(false),action_waiting(false),action_signaled(false),aborted(false),
handle(_handle),type(_type),event(threader->MakeEventSignal()),
recv_buffer(NULL),recv_buffer_size(1024),_current_recv_buffer_size(0),last_iolen(0)

{
	assert((type > cURLThread_Type_NOTHING && type < cURLThread_Type_LAST));
	assert((event != NULL));
	handle->running = true;
	handle->thread = this;	
}

cURLThread::~cURLThread()
{
	waiting = false;
	if(event != NULL)
	{
		event->DestroyThis();
		event = NULL;
	}
	if(recv_buffer != NULL)
	{
		delete [] recv_buffer;
		recv_buffer = NULL;
	}

	g_cURLManager.RemovecURLThread(this);
}

cURLHandle *cURLThread::GetHandle()
{
	return handle;
}

cURLThread_Type cURLThread::GetRunType()
{
	return type;
}

void cURLThread::EventSignal()
{
	assert((event != NULL));
	event->Signal();
}

void cURLThread::EventWait()
{
	assert((event != NULL));
	waiting = true;
	event->Wait();
	waiting = false;
}

bool cURLThread::IsWaiting()
{
	std::lock_guard<std::mutex> lock(action_mutex);
	return waiting || action_waiting;
}

bool cURLThread::SignalAction(SendRecv_Act act)
{
	{
		std::lock_guard<std::mutex> lock(action_mutex);
		if(action_waiting)
		{
			SetSenRecvAction(act);
			action_signaled = true;
			action_cv.notify_all();
			return true;
		}
	}

	if(!waiting)
		return false;

	SetSenRecvAction(act);
	EventSignal();
	return true;
}

void cURLThread::Abort()
{
	std::lock_guard<std::mutex> lock(action_mutex);
	aborted = true;
	action_cv.notify_all();
}

bool cURLThread::WaitForAction()
{
	std::unique_lock<std::mutex> lock(action_mutex);
	action_waiting = true;
	action_cv.wait(lock, [this] { return action_signaled || aborted; });
	action_waiting = false;
	action_signaled = false;
	return !aborted;
}

char *cURLThread::GetReceiveBuffer()
{
	return recv_buffer;
}

void cURLThread::SetRecvBufferSize(unsigned int size)
{
	if(size == 0)
		size = 1024;
	else if(size > (64*1024*1024)) // 64MB
		size = (64*1024*1024);

	recv_buffer_size = size;
}

void cURLThread::SetSenRecvAction(SendRecv_Act act)
{
	assert((act > SendRecv_Act_NOTHING && act < SendRecv_Act_LAST));
	send_recv_act = act;
}

void cURLThread::RunThread_Perform()
{
	if(handle->destroyed)
	{
		handle->lasterror = CURLE_ABORTED_BY_CALLBACK;
		return;
	}

	g_cURLManager.LoadcURLOption(handle);

	if(handle->lasterror != CURLE_OK)
		return;
	
	if((handle->lasterror = curl_easy_perform(handle->curl)) != CURLE_OK)
		return;

	handle->lasterror = curl_easy_getinfo(handle->curl, CURLINFO_ACTIVESOCKET, &handle->sockextr);
}

static void curl_send_FramAction(void *data)
{
	if(data == NULL)
		return;

	cURLThread *thread = (cURLThread*)data;
	cURLHandle *handle = thread->GetHandle();
	
	IPluginFunction *pFunc = handle->callback_Function[cURL_CallBack_SEND];
	assert((pFunc != NULL));
	if(handle->destroyed)
	{
		thread->SetSenRecvAction(SendRecv_Act_GOTO_END);
	}
	else if(pFunc != NULL)
	{
		cell_t result;
		pFunc->PushCell(handle->hndl);
		pFunc->PushCell(handle->lasterror);
		pFunc->PushCell(static_cast<cell_t>(thread->last_iolen));
		pFunc->PushCell(handle->UserData[UserData_Type_Send_Recv]);
		pFunc->Execute(&result);
		thread->SetSenRecvAction((SendRecv_Act)result);
	}

	thread->EventSignal();
}

static void curl_recv_FramAction(void *data)
{
	if(data == NULL)
		return;

	cURLThread *thread = (cURLThread*)data;
	cURLHandle *handle = thread->GetHandle();
	
	IPluginFunction *pFunc = handle->callback_Function[cURL_CallBack_RECV];
	assert((pFunc != NULL));
	if(handle->destroyed)
	{
		thread->SetSenRecvAction(SendRecv_Act_GOTO_END);
	}
	else if(pFunc != NULL)
	{
		cell_t result;
		pFunc->PushCell(handle->hndl);
		pFunc->PushCell(handle->lasterror);
		pFunc->PushStringEx(thread->GetReceiveBuffer(), thread->last_iolen, SM_PARAM_STRING_COPY|SM_PARAM_STRING_BINARY, 0);
		pFunc->PushCell(static_cast<cell_t>(thread->last_iolen));
		pFunc->PushCell(handle->UserData[UserData_Type_Send_Recv]);
		pFunc->Execute(&result);
		thread->SetSenRecvAction((SendRecv_Act)result);
	}
	thread->EventSignal();
}

void cURLThread::RunThread_Send_Recv()
{
	assert((handle->sockextr != CURL_SOCKET_BAD));

	if(handle->sockextr == CURL_SOCKET_BAD || event == NULL)
	{
		handle->lasterror = CURLE_SEND_ERROR;
		return;
	}

/* Select Action */
select_action:
	if(send_recv_act == SendRecv_Act_GOTO_SEND)
		goto act_send;
	else if(send_recv_act == SendRecv_Act_GOTO_RECV)
		goto act_recv;
	else if(send_recv_act == SendRecv_Act_GOTO_WAIT)
		goto act_wait;
	else if(send_recv_act == SendRecv_Act_GOTO_SEND_NO_WAIT)
		goto act_send_no_wait;
	else if(send_recv_act == SendRecv_Act_GOTO_RECV_NO_WAIT)
		goto act_recv_no_wait;
	else
		goto act_end;


/* Send Action */
act_send:
	if(!wait_on_socket(handle->sockextr, false, handle->send_timeout))
	{
		handle->lasterror = CURLE_OPERATION_TIMEDOUT;
		goto sm_send_frame;
	}

act_send_no_wait:
	if(handle->send_buffer.length() == 0)
	{
		handle->lasterror = CURLE_SEND_ERROR;	
		goto sm_send_frame;
	}

	handle->lasterror = curl_easy_send(handle->curl, handle->send_buffer.data(), handle->send_buffer.length(), &last_iolen);
	handle->send_buffer.clear();

	// put res to frame, let frame do action
sm_send_frame:
	smutils->AddFrameAction(curl_send_FramAction, this);

	EventWait();

	if(g_cURL_SM.IsShutdown())
		goto act_end;

	goto select_action;


/* Recv Action */
act_recv:
	if(!wait_on_socket(handle->sockextr, true, handle->recv_timeout))
	{
		handle->lasterror = CURLE_OPERATION_TIMEDOUT;
		goto sm_recv_frame;
	}

act_recv_no_wait:
	if(_current_recv_buffer_size != recv_buffer_size || recv_buffer == NULL)
	{
		if(recv_buffer != NULL)
		{
			delete [] recv_buffer;
			recv_buffer = NULL;
		}
		_current_recv_buffer_size = recv_buffer_size;
		recv_buffer = new char[_current_recv_buffer_size+1];
		memset(recv_buffer, 0, _current_recv_buffer_size+1);
	}

	handle->lasterror = curl_easy_recv(handle->curl, recv_buffer, _current_recv_buffer_size, &last_iolen);
	
sm_recv_frame:
	smutils->AddFrameAction(curl_recv_FramAction, this);

	EventWait();

	if(g_cURL_SM.IsShutdown())
		goto act_end;

	goto select_action;


/* Wait Action */
act_wait:
	if(g_cURL_SM.IsShutdown())
		goto act_end;

	// Until the plugin's signal. Ends for good when the handle was closed
	// or the extension unloads.
	if(!WaitForAction())
		goto act_end;

	if(g_cURL_SM.IsShutdown())
		goto act_end;
	goto select_action; // select action again



/* End Action */
act_end:
	return;
}


void cURLThread::RunThread(IThreadHandle *pHandle)
{
	if(type == cURLThread_Type_PERFORM)
	{
		RunThread_Perform();
	} else if(type == cURLThread_Type_SEND_RECV) {
		RunThread_Send_Recv();
	}
}


static void cUrl_Thread_Finish(void *data)
{
	if(data == NULL)
		return;

	cURLThread *thread = (cURLThread*)data;
	cURLHandle *handle = thread->GetHandle();

	// NULL: the handle was closed after the transfer ended and before this
	// frame; it is freed already.
	if(handle == NULL)
	{
		thread->EventSignal();
		return;
	}

	// The last progress report, before the complete callback. The plugin
	// may close the handle in it; then nothing else is called.
	if(thread->GetRunType() == cURLThread_Type_PERFORM)
	{
		bool stop = g_cURLManager.ReportFinalProgress(handle);
		handle = thread->GetHandle();
		if(handle == NULL)
		{
			thread->EventSignal();
			return;
		}
		// Too late to stop anything, but the plugin gets the result it
		// asked for, as when it stops a transfer earlier.
		if(stop && handle->lasterror == CURLE_OK)
		{
			handle->lasterror = CURLE_ABORTED_BY_CALLBACK;
		}
	}

	IPluginFunction *pFunc = handle->callback_Function[cURL_CallBack_COMPLETE];
	assert((pFunc != NULL));
	if(pFunc != NULL)
	{
		pFunc->PushCell(handle->hndl);
		pFunc->PushCell(handle->lasterror);
		pFunc->PushCell(handle->UserData[UserData_Type_Complete]);
		pFunc->Execute(NULL);
	}

	// The callback may have closed the handle (GetHandle() is NULL then) or
	// started the next transfer on it (it has another thread then). If
	// neither, the handle must forget this thread, which ends now.
	handle = thread->GetHandle();
	if(handle != NULL && handle->thread == thread)
	{
		handle->thread = NULL;
	}

	thread->EventSignal();
}

void cURLThread::OnTerminate(IThreadHandle *pHandle, bool cancel)
{
	bool destroyed;
	{
		std::lock_guard<std::mutex> lock(g_cURLManager.handle_state_mutex);
		handle->running = false;
		handle->finished = true;
		destroyed = handle->destroyed;
	}

	// The handle was closed during the transfer: its plugin gets no
	// callback (it may be unloaded). Nothing else knows the handle anymore,
	// so it is freed here, without waiting for a game frame that may never
	// come for this thread when the extension unloads.
	if(destroyed)
	{
		g_cURLManager.RemovecURLHandle(handle);
		delete this;
		return;
	}

	if(!g_cURL_SM.IsShutdown())
	{
		smutils->AddFrameAction(cUrl_Thread_Finish, this);
		
		EventWait();
	}
	delete this;
}

