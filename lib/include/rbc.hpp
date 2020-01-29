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

#include "consensus.pb.h"
#include "logger.hpp"

#include <bitset>
#include <unordered_set>

namespace fetch {
namespace consensus {
class AbstractNode;

/**
 * Reliable broadcast channel, which ensures consensus of messages acted upon by
 * honest nodes for broadcasting messages in the DKG
 */
class RBC {
  using tag_type = uint64_t;
  using hash_type = std::string;

  enum class MsgType : uint8_t {
    R_SEND, R_ECHO, R_READY, R_REQUEST, R_ANSWER
  };
  static std::string msgTypeToString(MsgType m);

  struct MsgCount {
    size_t e_d_, r_d_;

    MsgCount() : e_d_{0}, r_d_{0} {}
  };

  class Broadcasts {
    struct Broadcast { ///< information per tag
      std::string mbar_; ///< message
      hash_type dbar_; ///< hash of message
      std::unordered_map<hash_type, MsgCount> msgsCount_;
    };
    mutable std::mutex mutex_;
    std::unordered_map<tag_type, Broadcast> broadcasts_; ///< map from tag to broadcasts

  public:
    struct MsgCount receivedReady(tag_type tag, const hash_type &hash) {
      std::lock_guard<std::mutex> lock(mutex_);
      auto &msgsCount = broadcasts_[tag].msgsCount_[hash];
      msgsCount.r_d_++;
      return msgsCount;
    }

    bool setMbar(tag_type tag, const std::string &message);
    std::pair<bool, hash_type> setDbar(tag_type tag, hash_type hash);
    bool receivedEcho(tag_type tag, hash_type hash, uint32_t committee_size, uint32_t threshold);
    std::string getMbar(tag_type tag) const;
    void eraseMbar(tag_type tag);
    bool receivedRAnswer(tag_type tag, const std::string &message);
  };

  class Parties {
    struct Party { ///< information per party
      std::unordered_map<tag_type, std::bitset<sizeof(MsgType) * 8>> flags_;
      uint8_t deliver_s_;
      std::map<uint8_t, fetch::consensus::pb::Direct_RBC_Tag> undelivered_msg; //indexed by seq
      Party() {
        deliver_s_ = 1; // initialize sequence counter by 1
      }
    };

    mutable std::mutex mutex_;
    std::vector<Party> parties_;
  public:
    explicit Parties(uint32_t committee_size);

    void erase(uint32_t id, tag_type tag);
    bool setFlag(uint32_t id, tag_type tag, MsgType m);
    uint8_t getSeq(uint32_t id) const;
    bool incrementDeliver(const fetch::consensus::pb::Direct_RBC_Tag &tag);
    bool hasUndelivered(uint32_t rank) const;
    std::vector<fetch::consensus::pb::Direct_RBC_Tag> undelivered(uint32_t rank, uint32_t id);
  };

  std::set<std::string> committee_; ///< String ids of committee members
  uint32_t threshold_; ///< RBC threshold
  uint32_t rank_{0}; ///< Our index
  AbstractNode &node_; ///< For sending and receiving messages
  uint8_t committee_id_; ///< Identifier for this committee
  uint8_t ID_; ///< Channel ID
  uint8_t s{0}; ///< Sequence counter
  Parties parties_; ///< Information received from committee members
  Broadcasts broadcasts_; ///< Information about each message broadcasted via RBC
  std::unordered_set<tag_type> delivered_; ///< Messages that have passed RBC
  std::mutex mutex_deliver_;


  static fetch::consensus::Logger logger;

  /// Message handlers
  /// @{
  void onRSend(const fetch::consensus::pb::Direct_RBC_Tag &tag, const fetch::consensus::pb::Direct_RBC_Message &msg,
               uint32_t l);
  void onREcho(const fetch::consensus::pb::Direct_RBC_Tag &tag, const fetch::consensus::pb::Direct_RBC_Hash &msg,
               uint32_t l);
  void onRReady(const fetch::consensus::pb::Direct_RBC_Tag &tag, const fetch::consensus::pb::Direct_RBC_Hash &msg,
                uint32_t l);
  void onRRequest(const fetch::consensus::pb::Direct_RBC_Tag &msg, uint32_t l);
  void onRAnswer(const fetch::consensus::pb::Direct_RBC_Tag &tag, const fetch::consensus::pb::Direct_RBC_Message &msg,
                 uint32_t l);
  /// @}

  /// Helper functions
  /// @{
  tag_type getTag(const fetch::consensus::pb::Direct_RBC_Tag &tag_msg) const;
  void setTag(fetch::consensus::pb::Direct_RBC_Tag &dest, const fetch::consensus::pb::Direct_RBC_Tag &src) const;
  bool checkTag(const fetch::consensus::pb::Direct_RBC_Tag &tag);
  bool setMbar(tag_type tag, const fetch::consensus::pb::Direct_RBC_Message &msg, uint32_t l);
  bool setDbar(tag_type tag, const fetch::consensus::pb::Direct_RBC_Hash &msg);
  bool receivedEcho(tag_type tag, const fetch::consensus::pb::Direct_RBC_Hash &msg);
  struct MsgCount receivedReady(tag_type tag, const fetch::consensus::pb::Direct_RBC_Hash &msg);
  bool setPartyFlag(uint32_t l, tag_type tag, MsgType m);
  void sendReady(const fetch::consensus::pb::Direct_RBC_Tag &tag, const fetch::consensus::pb::Direct_RBC_Hash &msg);
  /// @}

  void deliver(const std::string &msg, uint32_t rank);

public:
  RBC(std::set<std::string> committee, AbstractNode &node, uint32_t threshold = UINT32_MAX, uint8_t committee_id = 0,
      uint8_t channel_id = 0);

  void broadcast(const fetch::consensus::pb::Broadcast &msg);
  void onRBC(const fetch::consensus::pb::Direct_RBC &rbc_msg, uint32_t l);

  uint32_t size() const;
};
}
}
