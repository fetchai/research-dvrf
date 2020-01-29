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

#include "localnode.hpp"
#include "simplenode.hpp"
#include "networknode.hpp"

using namespace fetch::consensus;

class DKGEventObserver : public EventObserver {
  std::mutex m_sign_;
  std::mutex m_dkg_;
  std::condition_variable cv_sign_;
  uint32_t committee_size_;
  std::set<std::string> signatures_;
  std::unordered_map<std::string, std::chrono::time_point<std::chrono::high_resolution_clock>> start_signing_;
  std::unordered_map<std::string, std::set<std::string>> public_keys_;
  Duration signature_start_to_end_{0};
public:
  explicit DKGEventObserver(uint32_t committee_size) : committee_size_{committee_size} {}

  void notifyNewConnection(const std::string &, const std::string &) override {}

  void notifyCommitteeSync(const std::string &) override {}

  void notifyRBCDeliver(const tag_type &, uint32_t, uint32_t) override {}

  void notifyGroupSignature(const std::string &, const std::string &) override {}

  void notifyDKGCompleted(const std::string &id, const Duration &, const std::string &public_key_str) override {
    std::unique_lock<std::mutex> mlock(m_dkg_);
    public_keys_[public_key_str].insert(id);
  }

  bool checkGroupPublicKeys() {
    std::unique_lock<std::mutex> mlock(m_dkg_);
    return public_keys_.size() == 1;
  }

  double
  waitForSignedMessage(uint32_t num_rounds = 1) {
    std::unique_lock<std::mutex> mlock(m_sign_);
    while (signatures_.size() < committee_size_) {
      cv_sign_.wait(mlock);
    }
    auto total_signature_ms = std::chrono::duration_cast<std::chrono::milliseconds>(signature_start_to_end_);
    double avg_total = double(total_signature_ms.count()) / double(committee_size_ * num_rounds);
    return avg_total;
  }

  void notifyBroadcastSignature(const std::string &id,
                                std::chrono::time_point<std::chrono::high_resolution_clock> broadcast_signature) override {
    std::lock_guard<std::mutex> lock(m_sign_);
    if (start_signing_.find(id) == start_signing_.end()) {
      start_signing_.insert({id, broadcast_signature});
    }
  }

  void notifySignedMessage(const std::string &id,
                           std::chrono::time_point<std::chrono::high_resolution_clock> computed_signature) override {
    std::unique_lock<std::mutex> mlock(m_sign_);
    if (start_signing_.find(id) != start_signing_.end()) {
      signature_start_to_end_ += (computed_signature - start_signing_.at(id));
    }
    signatures_.insert(id);
    mlock.unlock();
    cv_sign_.notify_one();
  }
};

template<class Drb>
std::vector<std::unique_ptr<fetch::consensus::AbstractDkgNode>>
build(bool networked, double latency, EventObserver &obs, uint32_t committee_size, uint32_t threshold,
      Scheduler &scheduler, bool signMessages) {
  using LocalNodeCrypto = LocalNode<Drb>;
  using SimpleNodeCrypto = SimpleNode<Drb>;
  using NetworkNodeCrypto = NetworkNode<Drb>;

  Drb::initCrypto();
  auto outputs = Drb::trustedDealer(committee_size, threshold);
  assert(outputs.size() == committee_size);

  if (networked) {
    std::vector<std::unique_ptr<NetworkNodeCrypto>> all_nodes;
    std::set<std::string> committee;
    for (uint16_t iv = 0; iv < committee_size; ++iv) {
      all_nodes.emplace_back(
              new NetworkNodeCrypto("Node" + std::to_string(iv), obs,
                                    scheduler.getIoContext(), 1024 + iv));
      committee.insert("Node" + std::to_string(iv));
    }
    for (auto &node : all_nodes) {
      node->setSignMessages(signMessages);
    }
    for (auto &node : all_nodes) {
      node->addAllNeighbours(all_nodes, threshold);
      node->setDkgOutput(committee, outputs[node->networkIndex()]);
    }
    std::vector<std::unique_ptr<fetch::consensus::AbstractDkgNode>> ret;
    for (auto &node : all_nodes) {
      ret.emplace_back(std::move(node));
    }
    return ret;
  }
  if (latency > 0) {
    std::vector<std::unique_ptr<LocalNodeCrypto>> all_nodes;
    std::set<std::string> committee;
    for (uint32_t iv = 0; iv < committee_size; ++iv) {
      all_nodes.emplace_back(
              new LocalNodeCrypto("Node" + std::to_string(iv), obs, scheduler, latency));
      committee.insert("Node" + std::to_string(iv));
    }
    for (auto &node : all_nodes) {
      node->addAllNeighbours(all_nodes, threshold);
      node->setDkgOutput(committee, outputs[node->networkIndex()]);
    }
    std::vector<std::unique_ptr<fetch::consensus::AbstractDkgNode>> ret;
    for (auto &node : all_nodes) {
      ret.emplace_back(std::move(node));
    }
    return ret;
  }
  std::vector<std::unique_ptr<SimpleNodeCrypto>> all_nodes;
  std::set<std::string> committee;
  for (uint32_t iv = 0; iv < committee_size; ++iv) {
    all_nodes.emplace_back(
            new SimpleNodeCrypto("Node" + std::to_string(iv), obs, scheduler));
    committee.insert("Node" + std::to_string(iv));
  }
  for (auto &node : all_nodes) {
    node->addAllNeighbours(all_nodes, threshold);
    node->setDkgOutput(committee, outputs[node->networkIndex()]);
  }

  std::vector<std::unique_ptr<fetch::consensus::AbstractDkgNode>> ret;
  for (auto &node : all_nodes) {
    ret.emplace_back(std::move(node));
  }
  return ret;
}