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

#include "committee.hpp"
#include "rbc.hpp"

namespace fetch {
namespace consensus {

/**
 * Processes the pre-DKG sync stage which ensures that all members are connected and ready
 * to begin before any messages in the DKG are broadcasted
 *
 * @tparam CryptoChoice Crypto type used in the DKG
 */
template<class CryptoProtocol>
class CommitteeManager {
  using CommitteeCrypto = Committee<CryptoProtocol>;

  uint8_t committeeId_;
  uint8_t preDkgChannelId_ = 10;
  uint32_t threshold_;
  AbstractDkgNode &node_;
  std::unique_ptr<CommitteeCrypto> committee_;
  std::unique_ptr<RBC> rbc_;
  std::unordered_map<std::string, uint32_t> idToIndex_;
  std::unordered_set<std::string> joined_;
  bool committeeSent_{false};
  std::mutex mutex_;

  fetch::consensus::Logger logger = fetch::consensus::Logger("CommitteeManager");

  bool checkCommittee(const fetch::consensus::pb::Broadcast_Committee &committee);
  void receivedCommittee(std::unique_lock<std::mutex> lock);

public:
  CommitteeManager(const std::set<std::string> &committee, AbstractDkgNode &node, uint32_t threshold,
                   uint8_t committeeId = 0);

  ~CommitteeManager();

  /// Message sending functions
  /// @{
  void broadcastCommittee(const std::set<std::string> &new_committee);
  void broadcastShares();
  void sendSignatureShare();
  /// @}

  /// Message handlers
  /// @{
  void onMessage(const fetch::consensus::pb::Direct &msg, const std::string &from);
  void onSignatureShare(const fetch::consensus::pb::Gossip_SignatureShare &share, const std::string &from);
  void onNewCommittee(const fetch::consensus::pb::Broadcast_Committee &committee, const std::string &from);
  void onNewCoefficients(const fetch::consensus::pb::Broadcast_Coefficients &coefficients,
                         const std::string &from_id);
  void onComplaints(const fetch::consensus::pb::Broadcast_Complaints &complaint, const std::string &from);
  void onExposedShares(const fetch::consensus::pb::Broadcast_Shares &shares, const std::string &from);
  /// @}

  void enableThresholdSigning(uint32_t t);
  void setDkgOutput(const std::set<std::string> &committee, const typename CryptoProtocol::DkgOutput &output);

  bool hasCommittee() const;
  uint32_t committeeSize() const;
};
}
}
