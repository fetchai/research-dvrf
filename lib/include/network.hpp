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

#include "asio.hpp"
#include <thread>

using asio::ip::tcp;

using Buffer = std::vector<uint8_t>;

template<typename T>
T from_string(const std::string &s) {
  T t;
  t.ParseFromString(s);
  return t;
}

template<typename T>
std::shared_ptr<Buffer> serialize(const T &t) {
  size_t size = t.ByteSize();
  Buffer data;
  data.resize(size);
  (void) t.SerializeWithCachedSizesToArray(data.data());
  return std::make_shared<Buffer>(data);
}

template<typename T>
T deserialize(const Buffer &buffer) {
  T t;
  t.ParseFromArray(buffer.data(), buffer.size());
  return t;
}

void asyncReadBuffer(asio::ip::tcp::socket &socket, uint32_t timeout,
                     std::function<void(std::error_code, std::shared_ptr<Buffer>)> handler);
void asyncWriteBuffer(asio::ip::tcp::socket &socket, std::shared_ptr<Buffer> s, uint32_t timeout);
void asyncWriteBuffer(asio::ip::tcp::socket &socket, std::shared_ptr<Buffer> s, uint32_t timeout,
                      std::function<void(std::error_code, std::size_t length)> handler);
std::error_code writeBuffer(asio::ip::tcp::socket &socket, std::shared_ptr<Buffer> s);

class IoContextPool {
  using context_work = asio::executor_work_guard<asio::io_context::executor_type>;
private:
  std::vector<std::shared_ptr<asio::io_context>> io_contexts_;
  std::vector<context_work> works_; // to keep he io_contexts running
  std::size_t next_io_context_;
  std::vector<std::shared_ptr<std::thread>> threads_;
  std::mutex mutex_;
public:
  explicit IoContextPool(std::size_t pool_size) : next_io_context_{0} {
    if (pool_size == 0)
      throw std::runtime_error("io_context_pool size is 0");
    // Give all the io_contexts work to do so that their run() functions will not
    // exit until they are explicitly stopped.
    for (std::size_t i = 0; i < pool_size; ++i) {
      auto io_context = std::make_shared<asio::io_context>();
      io_contexts_.emplace_back(io_context);
      works_.push_back(asio::make_work_guard(*io_context));
    }
  }

  ~IoContextPool() {
    join();
    stop();
  }

  void join() {
    for (auto &t : threads_)
      t->join();
  }

  void run() {
    // Create a pool of threads to run all of the io_contexts.
    for (auto &context : io_contexts_) {
      threads_.emplace_back(std::make_shared<std::thread>([&context]() { context->run(); }));
    }
  }

  void stop() {
    // Explicitly stop all io_contexts.
    for (auto &context : io_contexts_)
      context->stop();
  }

  asio::io_context &getIoContext() {
    std::lock_guard<std::mutex> lock(mutex_);
    // Use a round-robin scheme to choose the next io_context to use.
    asio::io_context &io_context = *io_contexts_[next_io_context_];
    next_io_context_ = (next_io_context_ + 1) % io_contexts_.size();
    return io_context;
  }
};

