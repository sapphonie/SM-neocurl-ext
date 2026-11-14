#include "pool.h"

#include <utility>

namespace neocurl {

Pool::Pool(size_t threadCount)
{
	for (size_t i = 0; i < threadCount; i++)
		m_threads.emplace_back(&Pool::Run, this);
}

Pool::~Pool()
{
	Stop();
}

void Pool::Submit(TaskId id, Task task)
{
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		if (m_isStopping)
			return;
		m_queue.push_back(QueuedTask{id, std::move(task)});
	}
	m_wakeUp.notify_one();
}

std::vector<TaskResult> Pool::TakeResults()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	return std::exchange(m_results, {});
}

void Pool::Stop()
{
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_isStopping = true;
		m_queue.clear();
		m_results.clear();
	}
	m_abort = true;
	m_wakeUp.notify_all();
	for (std::thread &thread : m_threads)
		if (thread.joinable())
			thread.join();
}

void Pool::Run()
{
	for (;;) {
		QueuedTask next;
		{
			std::unique_lock<std::mutex> lock(m_mutex);
			m_wakeUp.wait(lock, [this] { return m_isStopping || !m_queue.empty(); });
			if (m_isStopping)
				return;
			next = std::move(m_queue.front());
			m_queue.pop_front();
		}

		TaskResult result = next.task(m_abort);
		result.id = next.id;

		std::lock_guard<std::mutex> lock(m_mutex);
		if (m_isStopping)
			return;
		m_results.push_back(std::move(result));
	}
}

} // namespace neocurl
