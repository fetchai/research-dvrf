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

#include <vector>
#include <unordered_set>
#include "consensus.pb.h"

/**
 * Wrappers for protobuf messages
 */

class SignaturesShare {
private:
  fetch::consensus::pb::Gossip_SignatureShare msg_;
public:
  SignaturesShare(const std::string &message, const std::string &share) {
    msg_.set_share_sig(share);
    msg_.set_message(message);
  }

  SignaturesShare(const std::string &message, const std::string &share,
                  const std::pair<std::string, std::string> &pi) {
    msg_.set_share_sig(share);
    msg_.set_message(message);
    msg_.set_share_pi(pi.first);
    msg_.set_share_pi2(pi.second);
  }

  const fetch::consensus::pb::Gossip_SignatureShare &handle() const { return msg_; }
};

class PrivateShares {
private:
  fetch::consensus::pb::PrivateShares msg_;
public:
  explicit PrivateShares(const std::string &first, const std::string &second) {
    msg_.set_first(first);
    msg_.set_second(second);
  }

  const fetch::consensus::pb::PrivateShares &handle() const { return msg_; }
};

class Neighbour {
private:
  using ECDSASignature = std::vector<uint8_t>;
  fetch::consensus::pb::Neighbour msg_;
public:
  Neighbour(const std::string &id, uint16_t port, const std::string &ECDSAPublicKey,
            const std::pair<std::vector<uint8_t>, ECDSASignature> &signedDHPublicKey) {
    msg_.set_id(id);
    msg_.set_port(port);
    msg_.set_public_key(ECDSAPublicKey);
    for (uint16_t i = 0; i < signedDHPublicKey.first.size(); ++i) {
      msg_.add_dh_public_key(signedDHPublicKey.first[i]);
    }
    for (uint16_t i = 0; i < signedDHPublicKey.second.size(); ++i) {
      msg_.add_key_signature(signedDHPublicKey.second[i]);
    }
  }

  const fetch::consensus::pb::Neighbour &handle() const { return msg_; }
};

class Gossip {
private:
  fetch::consensus::pb::Gossip gossip_;
public:
  explicit Gossip(const std::string &serialized) {
    bool ok = gossip_.ParseFromString(serialized);
    assert(ok);
    (void) ok;
  }

  bool hasSigShare() const {
    return gossip_.has_sig_share();
  }

  const fetch::consensus::pb::Gossip_SignatureShare &sig_share() const {
    assert(hasSigShare());
    return gossip_.sig_share();
  }

  explicit Gossip(const SignaturesShare &msg) {
    auto *p = gossip_.mutable_sig_share();
    p->CopyFrom(msg.handle());
  }

  const fetch::consensus::pb::Gossip &handle() const { return gossip_; }
};