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

#define DEBUG_ON 1

#include <google/protobuf/text_format.h>

#include "rbc.hpp"
#include "node.hpp"
#include "sha256.hpp"

namespace fetch {
namespace consensus {
std::string toString(const google::protobuf::Message &msg) {
  std::string output;
  google::protobuf::TextFormat::PrintToString(msg, &output);
  return output;
}

Logger RBC::logger = fetch::consensus::Logger("RBC");

std::string RBC::msgTypeToString(MsgType m) {
  switch (m) {
    case MsgType::R_SEND:
      return "r_send";
    case MsgType::R_ECHO:
      return "r_echo";
    case MsgType::R_READY:
      return "r_ready";
    case MsgType::R_REQUEST:
      return "r_request";
    case MsgType::R_ANSWER:
      return "r_answer";
    default:
      assert(false);
      return "";
  }
}

bool RBC::Broadcasts::setMbar(tag_type tag, const std::string &message) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (broadcasts_[tag].mbar_.empty()) {
    broadcasts_[tag].mbar_ = message;
    return true;
  }
  return broadcasts_[tag].mbar_ == message;
}

std::pair<bool, RBC::hash_type> RBC::Broadcasts::setDbar(tag_type tag, hash_type hash) {
  std::lock_guard<std::mutex> lock(mutex_);
  broadcasts_[tag].dbar_ = hash;
  hash_type hash1;
  if (!broadcasts_[tag].mbar_.empty()) {
    hash1 = SHA256(broadcasts_[tag].mbar_).toString();
  }
  return std::make_pair(hash1 == hash, hash1);
}

bool RBC::Broadcasts::receivedEcho(tag_type tag, hash_type hash, uint32_t committee_size, uint32_t threshold) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto &msgsCount = broadcasts_[tag].msgsCount_[hash];
  msgsCount.e_d_++;
  return (msgsCount.e_d_ == committee_size - threshold and msgsCount.r_d_ <= threshold);
}

std::string RBC::Broadcasts::getMbar(tag_type tag) const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (broadcasts_.find(tag) == broadcasts_.end()) {
    return "";
  } else {
    return broadcasts_.at(tag).mbar_;
  }
}

void RBC::Broadcasts::eraseMbar(tag_type tag) {
  std::lock_guard<std::mutex> lock(mutex_);
  broadcasts_.erase(tag);
}

bool RBC::Broadcasts::receivedRAnswer(tag_type tag, const std::string &message) {
  std::lock_guard<std::mutex> lock(mutex_);
  // If have not set dbar then we did not send a request message
  if (broadcasts_[tag].dbar_.empty())
    return false;
  //Check the hash of the message
  hash_type hash1{SHA256(message).toString()};
  if (hash1 == broadcasts_[tag].dbar_) {
    if (broadcasts_[tag].mbar_.empty()) {
      broadcasts_[tag].mbar_ = message;
    } else {
      broadcasts_[tag].mbar_ = message;
    }
  } else {
    return false;
  }
  return true;
}

RBC::Parties::Parties(uint32_t committee_size) {
  parties_.resize(committee_size);
}

void RBC::Parties::erase(uint32_t id, tag_type tag) {
  std::lock_guard<std::mutex> lock(mutex_);
  parties_[id].flags_.erase(tag);
}

bool RBC::Parties::setFlag(uint32_t id, tag_type tag, MsgType m) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto &iter = parties_[id].flags_[tag];
  auto index = static_cast<uint32_t>(m);
  if (iter[index])
    return false;
  iter.set(index);
  return true;
}

uint8_t RBC::Parties::getSeq(uint32_t id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return parties_[id].deliver_s_;
}

bool RBC::Parties::incrementDeliver(const fetch::consensus::pb::Direct_RBC_Tag &tag) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (uint8_t(tag.seq()) == parties_[tag.rank()].deliver_s_) {
    ++parties_[tag.rank()].deliver_s_; //Increase counter
    return true;
  }
  if (uint8_t(tag.seq()) > parties_[tag.rank()].deliver_s_) {
    // Store tag of message for processing later
    if (parties_[tag.rank()].undelivered_msg.find(uint8_t(tag.seq())) == parties_[tag.rank()].undelivered_msg.end())
      parties_[tag.rank()].undelivered_msg.insert({uint8_t(tag.seq()), tag});
  }
  return false;
}

bool RBC::Parties::hasUndelivered(uint32_t rank) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return !parties_[rank].undelivered_msg.empty();
}

std::vector<fetch::consensus::pb::Direct_RBC_Tag> RBC::Parties::undelivered(uint32_t rank, uint32_t id) {
  std::vector<fetch::consensus::pb::Direct_RBC_Tag> res;
  auto iter = parties_[rank].undelivered_msg.begin();
  while (iter != parties_[rank].undelivered_msg.end() and iter->second.channel_id() == id
         and iter->second.seq() == parties_[rank].deliver_s_) {
    res.push_back(iter->second);
    ++parties_[rank].deliver_s_;
    iter = parties_[rank].undelivered_msg.erase(iter);
  }
  return res;
}

RBC::RBC(std::set<std::string> committee, AbstractNode &node, uint32_t threshold, uint8_t committee_id,
         uint8_t channel_id)
        : committee_{std::move(committee)}, threshold_{threshold}, node_{node}, committee_id_{committee_id},
          ID_{channel_id}, parties_{static_cast<uint32_t>(committee_.size())} {
  auto iter = committee_.find(node.id());
  assert(iter != committee_.end());
  rank_ = static_cast<uint32_t>(std::distance(committee_.begin(), iter));

  auto committee_size = static_cast<uint32_t>(committee_.size());
  if (threshold_ == UINT32_MAX) {
    // Set threshold depending on size of committee to the maximum value it can take
    if (committee_size % 3 == 0) {
      threshold_ = static_cast<uint32_t>(committee_size / 3 - 1);
    } else {
      threshold_ = static_cast<uint32_t>(committee_size / 3);
    }
  }
  // checking maximum asynchronous t-resilience
  assert(committee_size > 3 * threshold_);
  // checking minimum number of parties
  assert(committee_size > 1);
}

void RBC::onRBC(const fetch::consensus::pb::Direct_RBC &rbc_msg, uint32_t l) {
  auto payload_case = rbc_msg.payload_case();
  switch (payload_case) {
    case fetch::consensus::pb::Direct_RBC::kBroadcast:
      logger.trace("Node {} receiving r-broadcast from {}", rank_, l);
      onRSend(rbc_msg.tag(), rbc_msg.broadcast(), l);
      break;
    case fetch::consensus::pb::Direct_RBC::kEcho:
      logger.trace("Node {} receiving r-echo from {} hash {}", rank_, l, rbc_msg.echo().msg_hash());
      onREcho(rbc_msg.tag(), rbc_msg.echo(), l);
      break;
    case fetch::consensus::pb::Direct_RBC::kReady:
      logger.trace("Node {} receiving r-ready from {} hash {}", rank_, l, rbc_msg.ready().msg_hash());
      onRReady(rbc_msg.tag(), rbc_msg.ready(), l);
      break;
    case fetch::consensus::pb::Direct_RBC::kRequest:
      logger.trace("Node {} receiving r-request from {}", rank_, l);
      onRRequest(rbc_msg.tag(), l);
      break;
    case fetch::consensus::pb::Direct_RBC::kAnswer:
      logger.trace("Node {} receiving r-answer from {}", rank_, l);
      onRAnswer(rbc_msg.tag(), rbc_msg.answer(), l);
      break;
    case fetch::consensus::pb::Direct_RBC::PAYLOAD_NOT_SET:
      logger.error("Connection::process cannot process payload {} from {}", payload_case, rank_);
  }
}

void RBC::broadcast(const fetch::consensus::pb::Broadcast &msg) {
  DEBUG(logger, "RBC::Broadcast {} : {}", rank_, toString(msg));
  std::string serialized_msg;
  bool ok = msg.SerializeToString(&serialized_msg);
  assert(ok);
  (void) ok;

  // Put serialised message into RBC message
  fetch::consensus::pb::Direct direct_msg;
  auto *rbc_msg{direct_msg.mutable_rbc_msg()};
  auto *broadcast{rbc_msg->mutable_broadcast()};
  auto *tag{rbc_msg->mutable_tag()};
  broadcast->set_message(serialized_msg);
  tag->set_rank(rank_);
  tag->set_seq(++s);
  tag->set_channel_id(static_cast<uint32_t>(ID_));
  direct_msg.set_committee_id(committee_id_);
  node_.sendDirect(direct_msg);
  onRSend(*tag, *broadcast, rank_); // self sending. must be done before broadcast
}

bool RBC::setMbar(tag_type tag, const fetch::consensus::pb::Direct_RBC_Message &msg, uint32_t l) {
  bool res = broadcasts_.setMbar(tag, msg.message());
  if (!res) {
    logger.error("RBC({}): received bad r-send message from {}", rank_, l);
  }
  return res;
}

bool RBC::setDbar(tag_type tag, const fetch::consensus::pb::Direct_RBC_Hash &msg) {
  auto p = broadcasts_.setDbar(tag, msg.msg_hash());
  if (!p.first)
    logger.warn("Node {} tag {} received wrong hash {} <> {}", rank_, tag, p.second, msg.msg_hash());
  return p.first;
}

bool RBC::receivedEcho(tag_type tag, const fetch::consensus::pb::Direct_RBC_Hash &msg) {
  return broadcasts_.receivedEcho(tag, msg.msg_hash(), size(), threshold_);
}

struct RBC::MsgCount RBC::receivedReady(tag_type tag, const fetch::consensus::pb::Direct_RBC_Hash &msg) {
  return broadcasts_.receivedReady(tag, msg.msg_hash());
}

tag_type RBC::getTag(const fetch::consensus::pb::Direct_RBC_Tag &tag_msg) const {
  static_assert(sizeof(tag_type) >= sizeof(uint64_t), "Tag_type is too small.");
  tag_type tag = tag_msg.channel_id();
  tag <<= 48;
  tag |= tag_msg.rank();
  tag <<= 32;
  return (tag | uint64_t(tag_msg.seq()));
}

void RBC::setTag(fetch::consensus::pb::Direct_RBC_Tag &dest, const fetch::consensus::pb::Direct_RBC_Tag &src) const {
  dest.set_channel_id(src.channel_id());
  dest.set_rank(src.rank());
  dest.set_seq(src.seq());
}

void RBC::onRSend(const fetch::consensus::pb::Direct_RBC_Tag &tag, const fetch::consensus::pb::Direct_RBC_Message &msg,
                  uint32_t l) {
  DEBUG(logger, "RBC::onRSend {} : l {} msg {}", rank_, l, toString(msg));
  tag_type tag_int{getTag(tag)};
  if (!setPartyFlag(l, tag_int, MsgType::R_SEND)) {
    return;
  }
  logger.trace("RBC::onRsend {} : l {} receive msg tag {} from {} seq {}", rank_, l, tag_int, tag.rank(), tag.seq());
  if (l == tag.rank()) {
    if (setMbar(tag_int, msg, l)) {
      fetch::consensus::pb::Direct direct_msg;
      auto *rbc_msg{direct_msg.mutable_rbc_msg()};
      auto *r_echo{rbc_msg->mutable_echo()};
      setTag(*(rbc_msg->mutable_tag()), tag);
      r_echo->set_msg_hash(SHA256(msg.message()).toString());
      direct_msg.set_committee_id(committee_id_);
      node_.sendDirect(direct_msg);
      onREcho(rbc_msg->tag(), *r_echo, rank_); // self sending
    }
  } else {
    logger.error("RBC({}): received wrong r-send message of {} from {}", rank_, tag.rank(), l);
  }
}

void RBC::sendReady(const fetch::consensus::pb::Direct_RBC_Tag &tag, const fetch::consensus::pb::Direct_RBC_Hash &msg) {
  fetch::consensus::pb::Direct direct_msg;
  auto *rbc_msg{direct_msg.mutable_rbc_msg()};
  auto *r_ready{rbc_msg->mutable_ready()};
  setTag(*(rbc_msg->mutable_tag()), tag);
  r_ready->set_msg_hash(msg.msg_hash());
  direct_msg.set_committee_id(committee_id_);
  node_.sendDirect(direct_msg);
  onRReady(rbc_msg->tag(), *r_ready, rank_); // self sending.
}

void RBC::onREcho(const fetch::consensus::pb::Direct_RBC_Tag &tag, const fetch::consensus::pb::Direct_RBC_Hash &msg,
                  uint32_t l) {
  uint64_t tag_int{getTag(tag)};
  if (!setPartyFlag(l, tag_int, MsgType::R_ECHO)) {
    return;
  }
  logger.trace("RBC::onRecho {} : l {} receive msg tag {} from {} seq {}", rank_, l, tag_int, tag.rank(), tag.seq());
  if (receivedEcho(tag_int, msg)) {
    sendReady(tag, msg);
  }
}

void RBC::onRReady(const fetch::consensus::pb::Direct_RBC_Tag &tag, const fetch::consensus::pb::Direct_RBC_Hash &msg,
                   uint32_t l) {
  uint64_t tag_int{getTag(tag)};
  if (!setPartyFlag(l, tag_int, MsgType::R_READY)) {
    return;
  }
  logger.trace("RBC::onRready {} : l {} receive msg tag {} from {} seq {}", rank_, l, tag_int, tag.rank(), tag.seq());
  auto msgsCount = receivedReady(tag_int, msg);
  if (threshold_ > 0 and msgsCount.r_d_ == threshold_ + 1 and msgsCount.e_d_ < (size() - threshold_)) {
    sendReady(tag, msg);
  } else if (threshold_ > 0 and msgsCount.r_d_ == 2 * threshold_ + 1) {
    if (!setDbar(tag_int, msg)) {
      fetch::consensus::pb::Direct direct_msg;
      auto *rbc_msg{direct_msg.mutable_rbc_msg()};
      auto *request{rbc_msg->mutable_request()};
      setTag(*(rbc_msg->mutable_tag()), tag);
      request->set_msg_hash(msg.msg_hash());
      direct_msg.set_committee_id(committee_id_);
      uint32_t counter{0};
      const auto miners = committee_;
      auto im{miners.begin()};
      assert(2 * threshold_ + 1 <= size());
      while (counter < 2 * threshold_ + 1) {
        if (*im != node_.id()) {
          node_.sendDirect(direct_msg, *im);
          ++counter;
        }
        ++im;
      }
    } else if (tag.rank() != rank_ && checkTag(tag)) {
      logger.trace("Node {} deliver message from node {}", rank_, tag.rank());
      node_.getEventObserver().notifyRBCDeliver(tag_int, tag.rank(), rank_);
      std::string messageToSend = broadcasts_.getMbar(tag_int);
      deliver(messageToSend, tag.rank());
      std::lock_guard<std::mutex> lock(mutex_deliver_);
      delivered_.insert(tag_int);
    }
  } else {
    std::lock_guard<std::mutex> lock(mutex_deliver_);
    if (msgsCount.r_d_ == size() - 1 &&
        delivered_.find(tag_int) != delivered_.end()) { // all messages arrived let's clean
      broadcasts_.eraseMbar(tag_int);
      parties_.erase(l, tag_int);
    }
  }
}

void RBC::onRRequest(const fetch::consensus::pb::Direct_RBC_Tag &msg, uint32_t l) {
  uint64_t tag{getTag(msg)};
  if (!setPartyFlag(l, tag, MsgType::R_REQUEST)) {
    return;
  }
  logger.trace("RBC::onRrequest {} : l {} receive msg tag {} from {} seq {}", rank_, l, tag, msg.rank(), msg.seq());
  const std::string mbar = broadcasts_.getMbar(tag);
  if (!mbar.empty()) {
    fetch::consensus::pb::Direct direct_msg;
    auto *rbc_msg{direct_msg.mutable_rbc_msg()};
    auto *r_answer{rbc_msg->mutable_answer()};
    setTag(*(rbc_msg->mutable_tag()), msg);
    r_answer->set_message(mbar);
    direct_msg.set_committee_id(committee_id_);
    const auto miners = committee_;
    auto im = std::next(miners.begin(), l);
    node_.sendDirect(direct_msg, *im);
  }
}

void
RBC::onRAnswer(const fetch::consensus::pb::Direct_RBC_Tag &tag, const fetch::consensus::pb::Direct_RBC_Message &msg,
               uint32_t l) {
  uint64_t tag_int{getTag(tag)};
  logger.trace("RBC::onRAnswer {} : l {} receive msg tag {} from {} seq {}", rank_, l, tag_int, tag.rank(), tag.seq());
  if (!setPartyFlag(l, tag_int, MsgType::R_ANSWER)) {
    return;
  }
  if (!broadcasts_.receivedRAnswer(tag_int, msg.message()))
    return;

  if (tag.rank() != rank_ && checkTag(tag)) {
    logger.trace("Node {} deliver message on answer from node {}", rank_, tag.rank());
    node_.getEventObserver().notifyRBCDeliver(tag_int, tag.rank(), rank_);
    const std::string mbar = broadcasts_.getMbar(tag_int);
    assert(!mbar.empty());
    deliver(mbar, tag.rank());
    std::lock_guard<std::mutex> lock(mutex_deliver_);
    delivered_.insert(tag_int);
  }
}

void RBC::deliver(const std::string &msg, uint32_t rank) {
  const auto miners = committee_;
  std::string miner_id{*std::next(miners.begin(), rank)};
  node_.onBroadcast(msg, miner_id);
  //Try to deliver old messages
  if (parties_.hasUndelivered(rank)) {
    logger.warn("Node {} check old tags for node {}", rank_, rank);
    auto msgs = parties_.undelivered(rank, ID_);
    for (auto &m : msgs) {
      uint64_t old_tag{getTag(m)};
      logger.warn("Node {} deliver old tag {} for node {} seq {}", rank_, old_tag, rank, m.seq());
      const std::string mbar = broadcasts_.getMbar(old_tag);
      assert(!mbar.empty());
      node_.onBroadcast(mbar, miner_id);
    }
  }
}

bool RBC::checkTag(const fetch::consensus::pb::Direct_RBC_Tag &tag) {
  if (tag.channel_id() != ID_) {
    logger.warn("Node {} received message with wrong channel id", rank_);
    return false;
  }
  logger.trace("Node {} check tag of ready message", rank_);
  bool res = parties_.incrementDeliver(tag);
  if (!res) {
    logger.warn("Node {} tag {} sequence counter {} does not match tag sequence {} for node {}",
                rank_, getTag(tag), parties_.getSeq(tag.rank()), tag.seq(), tag.rank());
  }
  return res;
}

bool RBC::setPartyFlag(uint32_t l, tag_type tag, MsgType m) {
  bool res = parties_.setFlag(l, tag, m);
  if (!res) {
    logger.warn("RBC {} : l {} repeated msg type {} tag {}", rank_, l,
                msgTypeToString(m), tag);
  }
  return res;
}

uint32_t RBC::size() const {
  return static_cast<uint32_t>(committee_.size());
}
}
}
