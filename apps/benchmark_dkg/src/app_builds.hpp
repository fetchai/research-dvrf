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
  std::mutex m_synced_;
  std::mutex m_dkg_;
  std::mutex m_sign_;
  std::condition_variable cv_synced_;
  std::condition_variable cv_dkg_;
  std::condition_variable cv_sign_;
  uint32_t committee_size_;
  std::set<std::string> committee_synced_;
  std::set<std::string> dkg_completed_;
  std::set<std::string> signatures_;
  std::unordered_map<std::string, std::chrono::time_point<std::chrono::high_resolution_clock>> start_signing_;
  std::unordered_map<std::string, std::unordered_set<std::string>> group_signatures_;
  std::unordered_map<std::string, std::set<std::string>> public_keys_;
  std::chrono::time_point<std::chrono::high_resolution_clock> pre_sync_start_;
  std::unordered_map<std::string, std::chrono::time_point<std::chrono::high_resolution_clock>> pre_sync_end_;
  Duration pre_sync_total_{0};
  Duration group_sig_total_{0};
  Duration dkg_total_{0};
  Duration signature_start_to_end_{0};

public:
  explicit DKGEventObserver(uint32_t committee_size) : committee_size_{committee_size} {}

  void notifyNewConnection(const std::string &, const std::string &) override {}

  double
  waitForSignedMessage() {
    std::unique_lock<std::mutex> mlock(m_sign_);
    while (signatures_.size() < committee_size_)
      cv_sign_.wait(mlock);
    auto total_signature_ms = std::chrono::duration_cast<std::chrono::milliseconds>(signature_start_to_end_);
    double avg_total = double(total_signature_ms.count()) / double(committee_size_);
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

  void notifyGroupSignature(const std::string &message, const std::string &group_signature) override {
    std::lock_guard<std::mutex> mlock(m_sign_);
    group_signatures_[message].insert(group_signature);
  }

  bool checkGroupSignatures() {
    return group_signatures_.size() == 1 && group_signatures_.begin()->second.size() == 1;
  }

  double waitForCommitteeSync(std::chrono::time_point<std::chrono::high_resolution_clock> start) {
    std::unique_lock<std::mutex> mlock(m_synced_);
    pre_sync_start_ = start;
    while (committee_synced_.size() < committee_size_)
      cv_synced_.wait(mlock);
    std::cerr << "**All synced.**\n";
    auto pre_sync_ms = std::chrono::duration_cast<std::chrono::milliseconds>(pre_sync_total_);
    double avg = double(pre_sync_ms.count()) / double(committee_size_);
    return avg;
  }

  void notifyCommitteeSync(const std::string &id) override {
    std::unique_lock<std::mutex> mlock(m_synced_);
    auto end_time = std::chrono::high_resolution_clock::now();
    if (pre_sync_end_.find(id) == pre_sync_end_.end()) {
      pre_sync_end_.insert({id, end_time});
      pre_sync_total_ += end_time - pre_sync_start_;
    }
    committee_synced_.insert(id);
    mlock.unlock();
    cv_synced_.notify_one();
  }

  std::pair<double, double>
  waitForDKG() {
    std::unique_lock<std::mutex> mlock(m_synced_);
    while (dkg_completed_.size() < committee_size_)
      cv_dkg_.wait(mlock);
    auto group_sig_total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(group_sig_total_);
    double group_sig_avg = double(group_sig_total_ms.count()) / double(committee_size_);
    auto dkg_ms = std::chrono::duration_cast<std::chrono::milliseconds>(dkg_total_);
    double dkg_avg = double(dkg_ms.count()) / double(committee_size_);
    return std::make_pair(dkg_avg, group_sig_avg);
  }

  bool checkGroupPublicKeys() {
    std::unique_lock<std::mutex> mlock(m_dkg_);
    return public_keys_.size() == 1;
  }

  void notifyDKGCompleted(const std::string &id, const Duration &time, const std::string &public_key_str) override {
    std::unique_lock<std::mutex> mlock(m_dkg_);
    auto dkg_end = std::chrono::high_resolution_clock::now();
    if (dkg_completed_.find(id) == dkg_completed_.end()) {
      group_sig_total_ += time;
      assert(pre_sync_end_.find(id) != pre_sync_end_.end());
      dkg_total_ += (dkg_end - pre_sync_end_.at(id)) - time;
      dkg_completed_.insert(id);
      public_keys_[public_key_str].insert(id);
      mlock.unlock();
      cv_dkg_.notify_one();
    }
  }

  void notifyRBCDeliver(const tag_type &, uint32_t, uint32_t) override {};
};

template<class Drb>
std::vector<std::unique_ptr<fetch::consensus::AbstractDkgNode>>
build(bool networked, double latency, EventObserver &obs, uint32_t committee_size, uint32_t threshold,
      Scheduler &scheduler, bool signMessages) {

  using LocalNodeCrypto = LocalNode<Drb>;
  using SimpleNodeCrypto = SimpleNode<Drb>;
  using NetworkNodeCrypto = NetworkNode<Drb>;

  Drb::initCrypto();
  std::cerr << "**Building**\n";
  if (networked) {
    std::vector<std::unique_ptr<NetworkNodeCrypto>> all_nodes;
    std::set<std::string> committee;
    for (uint16_t iv = 0; iv < committee_size; ++iv) {
      all_nodes.emplace_back(
              new NetworkNodeCrypto("Node" + std::to_string(iv), obs,
                                    scheduler.getIoContext(), 1024 + iv));
      committee.insert("Node" + std::to_string(iv));
    }
    // Set signing preferences
    for (auto &n : all_nodes) {
      n->setSignMessages(signMessages);
    }
    for (auto &node : all_nodes) {
      node->addAllNeighbours(all_nodes, threshold);
    }
    std::vector<std::unique_ptr<fetch::consensus::AbstractDkgNode>> ret;
    for (auto &node : all_nodes) {
      ret.emplace_back(std::move(node));
    }
    return ret;

  }
  if (latency > 0) {
    std::vector<std::unique_ptr<LocalNodeCrypto>> all_nodes;
    for (uint32_t iv = 0; iv < committee_size; ++iv) {
      all_nodes.emplace_back(
              new LocalNodeCrypto("Node" + std::to_string(iv), obs, scheduler, latency));
    }
    for (auto &node : all_nodes) {
      node->addAllNeighbours(all_nodes, threshold);
    }
    std::vector<std::unique_ptr<fetch::consensus::AbstractDkgNode>> ret;
    for (auto &node : all_nodes) {
      ret.emplace_back(std::move(node));
    }
    return ret;
  }
  std::vector<std::unique_ptr<SimpleNodeCrypto>> all_nodes;
  for (uint32_t iv = 0; iv < committee_size; ++iv) {
    all_nodes.emplace_back(
            new SimpleNodeCrypto("Node" + std::to_string(iv), obs, scheduler));
  }
  for (auto &node : all_nodes) {
    node->addAllNeighbours(all_nodes, threshold);
  }
  std::vector<std::unique_ptr<fetch::consensus::AbstractDkgNode>> ret;
  for (auto &node : all_nodes) {
    ret.emplace_back(std::move(node));
  }
  return ret;
}