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

#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>

template<typename T>
class Queue {
private:
  std::queue<T> queue_;
  std::mutex mutex_;
  std::condition_variable conditionVariable_;

public:
  T pop() {
    std::unique_lock<std::mutex> mlock(mutex_);
    while (queue_.empty()) {
      conditionVariable_.wait(mlock);
    }
    auto item = std::move(queue_.front());
    queue_.pop();
    return item;
  }

  void push(const T &item) {
    std::unique_lock<std::mutex> mlock(mutex_);
    queue_.push(item);
    mlock.unlock();
    conditionVariable_.notify_one();
  }

  void push(T &&item) {
    std::unique_lock<std::mutex> mlock(mutex_);
    queue_.push(std::move(item));
    mlock.unlock();
    conditionVariable_.notify_one();
  }

  bool empty() const {
    std::unique_lock<std::mutex> mlock(mutex_);
    return queue_.empty();
  }

  size_t size() const {
    std::unique_lock<std::mutex> mlock(mutex_);
    return queue_.size();
  }
};
