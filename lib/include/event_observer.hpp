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

#include <chrono>
#include <string>

namespace fetch {
namespace consensus {
using Duration = std::chrono::duration<long int, std::nano>;
using tag_type = uint64_t;

class EventObserver {
public:
  virtual void notifyRBCDeliver(const tag_type &tag, uint32_t from_rank, uint32_t to_rank) = 0;
  virtual void notifyNewConnection(const std::string &id, const std::string &to) = 0;
  virtual void notifyCommitteeSync(const std::string &id) = 0;
  virtual void notifyDKGCompleted(const std::string &id, const Duration &time, const std::string &public_key_str) = 0;
  virtual void notifySignedMessage(const std::string &id,
                                   std::chrono::time_point<std::chrono::high_resolution_clock> computed_signature) = 0;
  virtual void notifyGroupSignature(const std::string &message, const std::string &signature) = 0;
  virtual void notifyBroadcastSignature(const std::string &id,
                                        std::chrono::time_point<std::chrono::high_resolution_clock> broadcast_signature) = 0;
  virtual ~EventObserver() = default;
};

class DefaultObserver : public EventObserver {
public:
  void notifyRBCDeliver(const tag_type &, uint32_t, uint32_t) override {}
  void notifyNewConnection(const std::string &, const std::string &) override {}
  void notifyCommitteeSync(const std::string &) override {}
  void notifyDKGCompleted(const std::string &, const Duration &, const std::string &) override {}
  void notifySignedMessage(const std::string &, std::chrono::time_point<std::chrono::high_resolution_clock>) override {}
  void notifyGroupSignature(const std::string &, const std::string &) override {}
  void
  notifyBroadcastSignature(const std::string &, std::chrono::time_point<std::chrono::high_resolution_clock>) override {}
  virtual ~DefaultObserver() = default;
};
}
}