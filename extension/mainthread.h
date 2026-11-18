// Copyright 2026 davenonymous
#ifndef _INCLUDE_SOURCEMOD_EXTENSION_MAINTHREAD_H_
#define _INCLUDE_SOURCEMOD_EXTENSION_MAINTHREAD_H_

#include "smsdk_ext.h"

/* How the extension's threads reach the main thread, and how the main
 * thread waits for them when the extension unloads.
 *
 * SourceMod's AddFrameAction() is not used for this: a queued frame action
 * cannot be withdrawn, so one that is still queued when the extension
 * unloads is called in the next frame, in a library that is gone. */
namespace mainthread {

typedef void (*Action)(void *data);

/* Called by the extension's SDK_OnLoad. */
void Load();

/* Called by the extension's SDK_OnUnload, after WaitForThreads(). What is
 * still queued is discarded. */
void Unload();

/* Calls run(data) in one of the next game frames. If the extension unloads
 * before that, discard(data) is called instead, when there is one. From any
 * thread. */
void Post(Action run, void *data, Action discard = nullptr);

/* Starts an IThread that WaitForThreads() waits for. The thread must call
 * ThreadEnded() with its IThreadHandle as the last thing its OnTerminate()
 * does. Main thread only. */
void StartThread(IThread *thread);
void ThreadEnded(IThreadHandle *handle);

/* Blocks until every thread of StartThread() has called ThreadEnded(). The
 * threads must have been told to end. Main thread only. */
void WaitForThreads();

} // namespace mainthread

#endif
