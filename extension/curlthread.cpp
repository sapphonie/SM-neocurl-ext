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
	res = select(sockfd + 1, &infd, &outfd, &errfd, &tv);
	return res;
}


cURLThread::cURLThread(cURLHandle *_handle, cURLThread_Type _type):
waiting(false),handle(_handle),type(_type),event(threader->MakeEventSignal()),
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
	return waiting;
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
	g_cURLManager.LoadcURLOption(handle);

	if(handle->lasterror != CURLE_OK)
		return;
	
	if((handle->lasterror = curl_easy_perform(handle->curl)) != CURLE_OK)
		return;

	handle->lasterror = curl_easy_getinfo(handle->curl, CURLINFO_LASTSOCKET, &handle->sockextr);
}

static void curl_send_FramAction(void *data)
{
	if(data == NULL)
		return;

	cURLThread *thread = (cURLThread*)data;
	cURLHandle *handle = thread->GetHandle();
	
	IPluginFunction *pFunc = handle->callback_Function[cURL_CallBack_SEND];
	assert((pFunc != NULL));
	if(pFunc != NULL)
	{
		cell_t result;
		pFunc->PushCell(handle->hndl);
		pFunc->PushCell(handle->lasterror);
		pFunc->PushCell(thread->last_iolen);
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
	if(pFunc != NULL)
	{
		cell_t result;
		pFunc->PushCell(handle->hndl);
		pFunc->PushCell(handle->lasterror);
		pFunc->PushStringEx(thread->GetReceiveBuffer(), thread->last_iolen, SM_PARAM_STRING_COPY|SM_PARAM_STRING_BINARY, 0);
		pFunc->PushCell(thread->last_iolen);
		pFunc->PushCell(handle->UserData[UserData_Type_Send_Recv]);
		pFunc->Execute(&result);
		thread->SetSenRecvAction((SendRecv_Act)result);
	}
	thread->EventSignal();
}

void cURLThread::RunThread_Send_Recv()
{
	assert((handle->sockextr != INVALID_SOCKET));

	if(handle->sockextr == INVALID_SOCKET || event == NULL)
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
	goto act_wait;


/* Wait Action */
act_wait:
	if(g_cURL_SM.IsShutdown())
		goto act_end;
	
	EventWait();

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
		
	IPluginFunction *pFunc = handle->callback_Function[cURL_CallBack_COMPLETE];
	assert((pFunc != NULL));
	if(pFunc != NULL)
	{
		pFunc->PushCell(handle->hndl);
		pFunc->PushCell(handle->lasterror);
		pFunc->PushCell(handle->UserData[UserData_Type_Complete]);
		pFunc->Execute(NULL);
	}

	thread->EventSignal();
}

void cURLThread::OnTerminate(IThreadHandle *pHandle, bool cancel)
{
	handle->running = false;
	if(!g_cURL_SM.IsShutdown())
	{
		smutils->AddFrameAction(cUrl_Thread_Finish, this);
		
		EventWait();
	}
	delete this;
}

