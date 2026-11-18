// Copyright 2026 davenonymous
#include "mainthread.h"

#include <condition_variable>
#include <deque>
#include <mutex>

namespace mainthread {

namespace {

struct Entry {
	Action run;
	void *data;
	Action discard;
};

std::mutex g_Mutex;
std::deque<Entry> g_Queue;
unsigned int g_RunningThreads = 0;
std::condition_variable g_ThreadEnded;

std::deque<Entry> TakeQueue()
{
	std::lock_guard<std::mutex> lock(g_Mutex);
	std::deque<Entry> entries;
	entries.swap(g_Queue);
	return entries;
}

void OnGameFrame(bool simulating)
{
	for (const Entry &entry : TakeQueue())
		entry.run(entry.data);
}

/* A thread that has ended leaves its handle to the main thread, which
 * joins it: only then has the thread left the extension's code. */
void JoinThread(void *data)
{
	IThreadHandle *handle = static_cast<IThreadHandle *>(data);
	handle->WaitForThread();
	handle->DestroyThis();
}

} // namespace

void Load()
{
	smutils->AddGameFrameHook(OnGameFrame);
}

void Unload()
{
	smutils->RemoveGameFrameHook(OnGameFrame);
	for (const Entry &entry : TakeQueue()) {
		if (entry.discard)
			entry.discard(entry.data);
	}
}

void Post(Action run, void *data, Action discard)
{
	std::lock_guard<std::mutex> lock(g_Mutex);
	g_Queue.push_back({run, data, discard});
}

void StartThread(IThread *thread)
{
	{
		std::lock_guard<std::mutex> lock(g_Mutex);
		g_RunningThreads++;
	}
	// Not Thread_AutoRelease: such a thread is detached and cannot be joined.
	threader->MakeThread(thread, Thread_Default);
}

void ThreadEnded(IThreadHandle *handle)
{
	Post(JoinThread, handle, JoinThread);

	std::lock_guard<std::mutex> lock(g_Mutex);
	g_RunningThreads--;
	g_ThreadEnded.notify_all();
}

void WaitForThreads()
{
	std::unique_lock<std::mutex> lock(g_Mutex);
	g_ThreadEnded.wait(lock, [] { return g_RunningThreads == 0; });
}

} // namespace mainthread
