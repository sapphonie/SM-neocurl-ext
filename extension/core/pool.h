/* A pool of worker threads that run queued tasks and keep their results
 * until the main thread collects them. */
#ifndef NEOCURL_CORE_POOL_H
#define NEOCURL_CORE_POOL_H

#include <stdint.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace neocurl {

using TaskId = uint64_t;

/* What a task ends with: an error code of its kind and, for tasks that
 * produce bytes, those bytes. */
struct TaskResult {
	TaskId id;
	int error;
	std::string output;
};

/* A task gets the pool's abort flag and must return soon after it is set. */
using Task = std::function<TaskResult(const std::atomic<bool> &abort)>;

class Pool {
public:
	explicit Pool(size_t threadCount);
	/* Stops like Stop(). */
	~Pool();
	Pool(const Pool &) = delete;
	Pool &operator=(const Pool &) = delete;

	/* Queues the task behind all others; the result carries id. */
	void Submit(TaskId id, Task task);

	/* The results of the tasks finished since the last call, in the order
	 * they finished. */
	std::vector<TaskResult> TakeResults();

	/* Aborts the running tasks, drops the queued ones and their results and
	 * joins the threads. Nothing is run after it returns. */
	void Stop();

private:
	struct QueuedTask {
		TaskId id;
		Task task;
	};

	void Run();

	std::mutex m_mutex;
	std::condition_variable m_wakeUp;
	std::deque<QueuedTask> m_queue;
	std::vector<TaskResult> m_results;
	bool m_isStopping = false;
	std::atomic<bool> m_abort{false};
	std::vector<std::thread> m_threads;
};

} // namespace neocurl

#endif // NEOCURL_CORE_POOL_H
