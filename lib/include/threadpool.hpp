#pragma once
//------------------------------------------------------------------------------
//
//   Copyright 2019-2020 Fetch.AI Limited
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
//------------------------------------------------------------------------------

#include <vector>
#include <thread>
#include <queue>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <future>

class ThreadPool {
  std::vector<std::thread> workers_;
  std::queue<std::function<void()>> tasks_;
  std::mutex queue_mutex_;
  std::condition_variable condition_;
  bool stop_;

public:
  ThreadPool(size_t nbThreads = 0) : stop_{false} {
    if (nbThreads == 0)
      nbThreads = std::thread::hardware_concurrency();
    if (nbThreads == 0) // hardware_concurrency is not supported (unlikely).
      nbThreads = 4;
    for (size_t i = 0; i < nbThreads; ++i) {
      workers_.emplace_back([this] {
        for (;;) {
          std::function<void()> task;
          {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            condition_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
            if (stop_ && tasks_.empty())
              return;
            task = std::move(tasks_.front());
            tasks_.pop();
          }
          task();
        }
      });
    }
  }

  static ThreadPool &getInstance(size_t nbThreads = 0) {
    static ThreadPool instance{nbThreads};
    return instance;
  }

  void stop() {
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      stop_ = true;
    }
    condition_.notify_all();
    for (std::thread &worker : workers_) {
      worker.join();
    }
  }

  ~ThreadPool() {
    if (!stop_)
      stop();
  }

  template<typename F, typename...Args>
  std::future<typename std::result_of<F(Args...)>::type> enqueue(F &&f, Args &&... args) {
    using return_type = typename std::result_of<F(Args...)>::type;

    auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...));

    std::future<return_type> res = task->get_future();
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      // don't allow enqueueing after stopping the pool
      if (stop_)
        throw std::runtime_error("enqueue on stopped ThreadPool");
      tasks_.emplace([task]() { (*task)(); });
    }
    condition_.notify_one();
    return res;
  }
};  
