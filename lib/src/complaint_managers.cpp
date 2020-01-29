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

#include "complaint_managers.hpp"

namespace fetch {
namespace consensus {

ComplaintsManager::ComplaintsManager(uint32_t committeeSize) : committeeSize_{committeeSize} {}

void ComplaintsManager::addComplaintAgainst(const std::string &complaint, const std::string &nodeId) {
  std::lock_guard<std::mutex> lock(mutex_);
  complaintsCounter_[complaint].insert(nodeId);
}

void ComplaintsManager::addComplaintsFrom(const fetch::consensus::pb::Broadcast_Complaints &complaint,
                                          const std::string &from, const std::set<std::string> &cabinet) {
  std::lock_guard<std::mutex> lock{mutex_};

  // already received complaints message then return
  if (complaintsReceived_.find(from) != complaintsReceived_.end()) {
    return;
  }

  complaintsReceived_.insert(from);
  std::unordered_set<std::string> complaintsFromSender;
  for (auto ii = 0; ii < complaint.nodes_size(); ++ii) {
    // Keep track of the nodes which are included in complaint. If there are duplicates then ignore
    if (complaintsFromSender.find(complaint.nodes(ii)) != complaintsFromSender.end()) {
      continue;
    } else if (cabinet.find(complaint.nodes(ii)) != cabinet.end()) {
      complaintsFromSender.insert(complaint.nodes(ii));
      complaintsCounter_[complaint.nodes(ii)].insert(from);
    }
  }
}

std::unordered_set<std::string> ComplaintsManager::complaintsAgainstSelf(const std::string &nodeId) const {
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_.load());
  if (complaintsCounter_.find(nodeId) == complaintsCounter_.end()) {
    return {};
  }
  return complaintsCounter_.at(nodeId);
}

std::set<std::string> ComplaintsManager::complaints() const {
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_.load());
  return complaints_;
}

bool ComplaintsManager::findComplaint(const std::string &complaint_address,
                                      const std::string &complainer_address) const {
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_.load());
  auto iter = complaintsCounter_.find(complaint_address);
  if (iter == complaintsCounter_.end()) {
    return false;
  }
  return (complaintsCounter_.at(complaint_address).find(complainer_address) !=
          complaintsCounter_.at(complaint_address).end());
}

uint32_t ComplaintsManager::complaintsCount(std::string const &id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto iter = complaintsCounter_.find(id);
  if (iter == complaintsCounter_.end())
    return 0;
  return static_cast<uint32_t>(iter->second.size());
}

bool ComplaintsManager::isFinished(uint32_t threshold) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (complaintsReceived_.size() == committeeSize_ - 1) {
    assert(!finished_.load());
    // Members which have received over threshold number of complaints are disqualified
    for (const auto &member : complaintsCounter_) {
      if (member.second.size() > threshold) {
        complaints_.insert(member.first);
      }
    }
    finished_.store(true);
    return true;
  }
  return false;
}

void ComplaintsManager::clear() {
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_.load());
  complaintsCounter_.clear();
  complaints_.clear();
}

ComplaintsAnswerManager::ComplaintsAnswerManager(uint32_t committeeSize) : committeeSize_{committeeSize} {}

void ComplaintsAnswerManager::init(const std::set<std::string> &complaints) {
  std::lock_guard<std::mutex> lock{mutex_};
  std::copy(complaints.begin(), complaints.end(), std::inserter(complaints_, complaints_.begin()));
}

void ComplaintsAnswerManager::addComplaintAgainst(const std::string &miner) {
  std::lock_guard<std::mutex> lock{mutex_};
  complaints_.insert(miner);
}

bool ComplaintsAnswerManager::addAnswerFrom(const std::string &from) {
  std::lock_guard<std::mutex> lock{mutex_};
  if (complaintAnswersReceived_.find(from) == complaintAnswersReceived_.end()) {
    complaintAnswersReceived_.insert(from);
    return true;
  }
  return false;
}

bool ComplaintsAnswerManager::isFinished() {
  std::lock_guard<std::mutex> lock{mutex_};
  if (complaintAnswersReceived_.size() == committeeSize_ - 1) {
    finished_.store(true);
    return true;
  }
  return false;
}

std::set<std::string> ComplaintsAnswerManager::buildQual(const std::set<std::string> &miners) {
  std::lock_guard<std::mutex> lock{mutex_};
  assert(finished_ == true);
  std::set<std::string> qual;
  std::set_difference(miners.begin(), miners.end(), complaints_.begin(), complaints_.end(),
                      std::inserter(qual, qual.begin()));
  return qual;
}

void ComplaintsAnswerManager::clear() {
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_ == true);
  complaints_.clear();
  complaintAnswersReceived_.clear();
}

void QualComplaintsManager::addComplaintAgainst(const std::string &id) {
  std::lock_guard<std::mutex> lock(mutex_);
  complaints_.insert(id);
}

std::set<std::string> QualComplaintsManager::complaints() const {
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_ == true);
  return complaints_;
}

bool QualComplaintsManager::addQualComplaintsFrom(const std::string &id) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (complaintsReceived_.find(id) == complaintsReceived_.end()) {
    complaintsReceived_.insert(id);
    return true;
  }
  return false;
}

size_t QualComplaintsManager::complaintsSize() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return complaints_.size();
}

bool QualComplaintsManager::complaintsFind(const std::string &id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return complaints_.find(id) != complaints_.end();
}

bool QualComplaintsManager::isFinished(uint32_t qual_size) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (complaintsReceived_.size() == qual_size - 1) {
    finished_ = true;
    return true;
  }
  return false;
}

void QualComplaintsManager::clear() {
  std::lock_guard<std::mutex> lock{mutex_};
  assert(finished_ == true);
  complaints_.clear();
  complaintsReceived_.clear();
  finished_ = false;
}
}
}