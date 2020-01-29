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

#include "client.hpp"
#include "scheduler.hpp"

#include <fstream>

using namespace fetch::consensus;

class DKGEventObserver : public EventObserver {
  std::mutex m_sign_;
  std::mutex m_dkg_;
  std::condition_variable cv_sign_;
  std::condition_variable cv_dkg_;
  bool all_connections_{false};
  bool dkg_completed_{false};
  bool signing_completed_{false};
public:
  DKGEventObserver() = default;

  void notifyCommitteeSync(const std::string &) override {}

  void notifyRBCDeliver(const tag_type &, uint32_t, uint32_t) override {}

  void notifyGroupSignature(const std::string &, const std::string &) override {}

  void notifyBroadcastSignature(const std::string &,
                                std::chrono::time_point<std::chrono::high_resolution_clock>) override {}

  void notifyNewConnection(const std::string &, const std::string &) override {
    std::unique_lock<std::mutex> mlock(m_dkg_);
    all_connections_ = true;
    mlock.unlock();
    cv_dkg_.notify_one();
  }

  void waitForConnections() {
    std::unique_lock<std::mutex> mlock(m_dkg_);
    while (!all_connections_) {
      cv_dkg_.wait(mlock);
    }
  }

  void notifyDKGCompleted(const std::string &, const Duration &, const std::string &) override {
    std::unique_lock<std::mutex> mlock(m_dkg_);
    dkg_completed_ = true;
    mlock.unlock();
    cv_dkg_.notify_one();
  }

  void waitForDKG() {
    std::unique_lock<std::mutex> mlock(m_dkg_);
    while (!dkg_completed_) {
      cv_dkg_.wait(mlock);
    }
  }

  void waitForSignedMessage() {
    std::unique_lock<std::mutex> mlock(m_sign_);
    while (!signing_completed_) {
      cv_sign_.wait(mlock);
    }
  }

  void notifySignedMessage(const std::string &,
                           std::chrono::time_point<std::chrono::high_resolution_clock>) override {
    std::unique_lock<std::mutex> mlock(m_sign_);
    signing_completed_ = true;
    mlock.unlock();
    cv_sign_.notify_one();
  }
};

template<class CryptoType>
std::unique_ptr<fetch::consensus::AbstractDkgNode>
build(uint16_t port, uint16_t serverPort, uint32_t nbNodes, uint32_t threshold, EventObserver &obs,
      Scheduler &scheduler, bool sign) {
  CryptoType::initCrypto();
  auto client = std::unique_ptr<Client<CryptoType>>(
          new Client<CryptoType>{"client" + std::to_string(port), obs, scheduler.getIoContext(), port, nbNodes,
                                 threshold});
  client->setSignMessages(sign);
  client->connectServer(client->ip(), serverPort);
  return std::move(client);
}