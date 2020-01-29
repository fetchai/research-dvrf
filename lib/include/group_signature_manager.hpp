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

#include <mutex>
#include <unordered_map>

namespace fetch {
namespace consensus {

template<class CryptoType>
class GroupSignatureManager {

  using MessagePayload = typename CryptoType::MessagePayload;
  using Signature = typename CryptoType::Signature;

  const uint32_t threshold_; // Threshold number of signatures to compute group signature
  std::unordered_map<MessagePayload,
          std::unordered_map<uint32_t, Signature>> signatureShares_;
  std::unordered_map<MessagePayload, Signature> signedMessages_;
  mutable std::mutex mutex_;
public:
  explicit GroupSignatureManager(uint32_t threshold) : threshold_{threshold} {}

  void addSignatureShares(const MessagePayload &message, const std::pair<std::size_t, Signature> &share) {
    std::lock_guard<std::mutex> lock{mutex_};
    if (signedMessages_.find(message) != signedMessages_.end()) {
      return;
    }
    auto iter = signatureShares_.find(message);
    if (iter == signatureShares_.end()) {
      signatureShares_.insert({message, {share}});
    } else if (iter->second.size() < threshold_) {
      signatureShares_[message].insert(share);
    }
  }

  void addSignedMessage(const MessagePayload &message, const Signature &sig) {
    std::lock_guard<std::mutex> lock{mutex_};
    assert(signedMessages_.find(message) == signedMessages_.end());
    signedMessages_.insert({message, sig});
    signatureShares_.erase(message);
  }

  size_t numSignatureShares(const MessagePayload &message) const {
    std::lock_guard<std::mutex> lock{mutex_};
    auto iter = signatureShares_.find(message);
    if (iter == signatureShares_.end())
      return 0;
    return iter->second.size();
  }

  const std::unordered_map<uint32_t, Signature> signatureShares(const MessagePayload &message) const {
    std::lock_guard<std::mutex> lock{mutex_};
    auto iter = signatureShares_.find(message);
    if (iter == signatureShares_.end())
      return {};
    return signatureShares_.at(message);
  }

  std::string groupSignature(const MessagePayload &message) const {
    std::lock_guard<std::mutex> lock(mutex_);
    assert(signedMessages_.find(message) != signedMessages_.end());
    return signedMessages_.at(message).toString();
  }

  bool signatureCompleted(const MessagePayload &message) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return signedMessages_.find(message) != signedMessages_.end();
  }
};

}
}