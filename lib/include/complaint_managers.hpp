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

#include <unordered_map>
#include "logger.hpp"
#include "messages.hpp"

namespace fetch {
namespace consensus {

/**
 * These classes manage the complaints, complaint answers and qual complaints in
 * the DKG
 */

class ComplaintsManager {
  uint32_t committeeSize_;
  std::unordered_map<std::string, std::unordered_set<std::string>> complaintsCounter_;
  std::set<std::string> complaints_;
  std::unordered_set<std::string> complaintsReceived_;
  std::atomic<bool> finished_{false};
  mutable std::mutex mutex_;
  static fetch::consensus::Logger logger;

public:
  ComplaintsManager(uint32_t committeeSize);

  void addComplaintAgainst(const std::string &complaint, const std::string &nodeId);
  void addComplaintsFrom(const fetch::consensus::pb::Broadcast_Complaints &complaint, const std::string &from,
                         const std::set<std::string> &cabinet);
  bool isFinished(uint32_t threshold);
  void clear();

  std::unordered_set<std::string> complaintsAgainstSelf(const std::string &nodeId) const;
  std::set<std::string> complaints() const;
  bool findComplaint(const std::string &complaint_address, const std::string &complainer_address) const;
  uint32_t complaintsCount(std::string const &id) const;
};

class ComplaintsAnswerManager {
  uint32_t committeeSize_;
  std::set<std::string> complaints_;
  std::unordered_set<std::string> complaintAnswersReceived_;
  std::atomic<bool> finished_{false};
  std::mutex mutex_;

public:
  ComplaintsAnswerManager(uint32_t committeeSize);

  void init(const std::set<std::string> &complaints);
  void addComplaintAgainst(const std::string &miner);
  bool addAnswerFrom(const std::string &from);
  bool isFinished();
  std::set<std::string> buildQual(const std::set<std::string> &miners);
  void clear();
};

class QualComplaintsManager {
  std::set<std::string> complaints_;
  std::unordered_set<std::string> complaintsReceived_;
  std::atomic<bool> finished_{false};
  mutable std::mutex mutex_;

public:
  QualComplaintsManager() = default;

  void addComplaintAgainst(const std::string &id);
  bool addQualComplaintsFrom(const std::string &id);
  bool isFinished(uint32_t qual_size);
  void clear();

  std::set<std::string> complaints() const;
  size_t complaintsSize() const;
  bool complaintsFind(const std::string &id) const;
};
}
}