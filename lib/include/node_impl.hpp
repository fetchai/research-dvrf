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

#include "node.hpp"
#include "committee_manager_impl.hpp"

namespace fetch {
namespace consensus {

template<class CryptoProtocol, class Derived>
Derived &Node<CryptoProtocol, Derived>::derived() {
  return *(static_cast<Derived *>(this));
}

template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::receivedHandshake() {
  if (committeeManager_ and (privateChannelCiphers_.size() + 1) == committeeManager_->committeeSize() and
      !committeeManager_->hasCommittee()) {
    committeeManager_->broadcastCommittee(neighbourhood_.networkMembers());
  }
}

/**
 * @return Index identifier of this node
 */
template<class CryptoProtocol, class Derived>
uint32_t Node<CryptoProtocol, Derived>::networkIndex() const {
  return neighbourhood_.networkIndex(id_);
}

/**
 * @return Number of nodes in network, including self
 */
template<class CryptoProtocol, class Derived>
std::size_t Node<CryptoProtocol, Derived>::networkSize() const {
  return neighbourhood_.networkSize();
}

/**
 * Add a node to your set of connections
 *
 * @param newNodes Set of nodes your new neighbour is aware of
 * @param neighbour Node to be added to connections
 */
template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::addNewNeighbour(const std::set<std::string> &newNodes, Derived &neighbour) {
  std::unique_lock<std::mutex> lock(mutex_);
  logger.trace("addNewNeighbour {} nodes {} from {}", id_, t_to_string(newNodes),
               neighbour.id());
  std::set<std::string> diff = neighbourhood_.networkDiff(newNodes);
  if (!diff.empty()) {
    derived().join(diff, neighbour);
  }
  lock.unlock();
  onNewNeighbour();
}

/**
 * State transition trigger dependent on number of nodes you have connected to
 */
template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::onNewNeighbour() {
  std::lock_guard<std::mutex> lock(mutex_);
  logger.trace("onNewNeighbour node {} neighbours {} committee {}", id(),
               neighbourhood_.neighboursSize(), bool(committeeManager_));
  if (committeeManager_ and (neighbourhood_.neighboursSize() + 1) == committeeManager_->committeeSize()) {
    // Start handshakes with everyone
    for (const auto &member : neighbourhood_.networkMembers()) {
      if (member != id_) {
        std::lock_guard<std::mutex> lock(handshakeMutex_);
        startHandShake(member);
      }
    }
  }
}

/**
 * @return Unique identifier for each message
 */
template<class CryptoProtocol, class Derived>
AbstractDkgNode::GossipKey Node<CryptoProtocol, Derived>::gossipId() {
  GossipKey gossipId = ((networkIndex() << 16) + gossipCounter_);
  ++gossipCounter_;
  return gossipId;
}

template<class CryptoProtocol, class Derived>
Node<CryptoProtocol, Derived>::Node(std::string id, EventObserver &eventObserver)
        : AbstractDkgNode{std::move(id), eventObserver}, neighbourhood_{id_} {

  // Generate ecdsa keys
  ecdsaKey_.generateKeys();

  // Generate Diffie Hellman key pair
  const char *key_type = "25519";
  int err = noise_dhstate_new_by_name(&dhKeys_, key_type);
  if (err != NOISE_ERROR_NONE) {
    noise_perror(key_type, err);
  }
  err = noise_dhstate_generate_keypair(dhKeys_);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("generate keypair", err);
    noise_dhstate_free(dhKeys_);
  }

  // Sign DH public key with ecdsa key
  std::vector<uint8_t> publicKey;
  publicKey.resize(noise_dhstate_get_public_key_length(dhKeys_));
  err = noise_dhstate_get_public_key(dhKeys_, &publicKey[0], noise_dhstate_get_public_key_length(dhKeys_));
  if (err != NOISE_ERROR_NONE) {
    noise_perror("get public key", err);
  }
  ECDSASignature signature;
  std::string publicKeyStr{publicKey.begin(), publicKey.end()};
  ecdsaKey_.sign(SHA256(publicKeyStr), signature);
  signedDHKey_ = std::make_pair(publicKey, signature);
}

template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::addNeighbour(Derived &node) {
  logger.trace("addNeighbour {} node {}", id_, node.id());
  if (neighbourhood_.updateNeighbour(node)) {
    neighbourhood_.join(derived());
    eventObserver_.notifyNewConnection(id_, node.id());
    onNewNeighbour();
  }
}

/**
 * On message relating to new information about nodes in the network
 *
 * @param newNodes String identifiers of new nodes
 * @param from Node from which the message originated
 */
template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::onJoin(const std::set<std::string> &newNodes, AbstractNode &from) {
  logger.trace("onJoin {} nodes {} from {}", id_, t_to_string(newNodes), from.id());

  std::set<std::string> reallyNewNodes;
  // first, if it is a new neighbour, let's send the known nodes minus the new nodes
  if (neighbourhood_.updateNeighbour(dynamic_cast<Derived &>(from))) {
    reallyNewNodes.insert(from.id()); // the new neighbour need to be propagated too.
    addNewNeighbour(newNodes, dynamic_cast<Derived &>(from));
    eventObserver_.notifyNewConnection(id_, from.id());
  }

  // second, let's send the new nodes to the known neighbours (minus the origin of the update)
  for (const auto &newNode : newNodes) {
    if (newNode != id_ && neighbourhood_.updateNetwork(newNode)) {
      reallyNewNodes.insert(newNode);
    }
  }

  if (!reallyNewNodes.empty()) {
    neighbourhood_.join(reallyNewNodes, derived(), dynamic_cast<Derived &>(from));
  }
}

/**
 * Function for sending messages via gossip (ideally use only when not fully connected other
 * wise will experience a lot of delays in messages)
 *
 * @param message Message to be sent
 * @param gossipKey Unique identifier of message
 */
template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::sendGossip(const Gossip &message, GossipKey gossipKey) {
  logger.trace("Node {} send gossip step {}", id_, gossipKey);
  std::string serialisedMsg;
  bool ok = message.handle().SerializeToString(&serialisedMsg);
  assert(ok);
  (void) ok;
  if (gossipKey == 0) {
    gossipKey = gossipId();
  }
  ECDSASignature signature;
  if (signAllMessages_) {
    ecdsaKey_.sign(SHA256(serialisedMsg), signature);
  }
  neighbourhood_.gossip(gossipKey, true, serialisedMsg, signature, id_, derived());
}

/**
 * Send a message directly to either a since peer, or all peers (broadcast)
 *
 * @param msg Message to be sent
 * @param peerId String identifier of target node, or if empty then broadcast to all connections
 */
template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::sendDirect(const fetch::consensus::pb::Direct &msg, const std::string &peerId) {
  assert(msg.has_committee_id());
  std::string serialisedMsg;
  bool ok = msg.SerializeToString(&serialisedMsg);
  assert(ok);
  (void) ok;
  ECDSASignature signature;
  if (signAllMessages_) {
    ecdsaKey_.sign(SHA256(serialisedMsg), signature);
  }
  if (peerId.empty()) {
    neighbourhood_.broadcast(gossipId(), false, serialisedMsg, signature, id_, derived());
  } else {
    neighbourhood_.unicast(gossipId(), false, serialisedMsg, signature, id_, peerId, derived());
  }
}

/**
 * Update list of gossip ids seen

 * @param gossipKey Identifier to update internal cache with
 * @return Whether key is new or not
 */
template<class CryptoProtocol, class Derived>
bool Node<CryptoProtocol, Derived>::updateGossip(GossipKey gossipKey) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto pair = gossips_.insert(gossipKey);
  return pair.second;
}

/**
 * Message handler for gossip messages
 *
 * @param gossipKey Unique identifier for message
 * @param gossip Whether the message is to be gossiped or not
 * @param message Message
 * @param emitter Origin of message
 * @param from Node from which you received the message
 */
template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::onGossip(GossipKey gossipKey, bool gossip, const std::string &message,
                                           const ECDSASignature &signature,
                                           const std::string &emitter, AbstractNode &from) {
  // Verify ECDSA signature
  if (signAllMessages_) {
    ECDSAKey verification_key;
    verification_key.setPublicKey(neighbourhood_.getNeighbour(from.id())->ECDSAPublicKey());
    if (!verification_key.verify(SHA256(message), signature)) {
      logger.warn("onGossip {} received msg with invalid ecdsa signature from {}", id_, from.id());
      return;
    }
  }

  logger.trace("onGossip {} step {} emitter {} from {}", id_, gossipKey, emitter, from.id());
  assert(neighbourhood_.check(from.id()));
  if (!gossip) {
    fetch::consensus::pb::Direct msg;
    msg.ParseFromString(message);
    if (msg.has_handshake()) {
      onHandshake(msg.handshake(), from.id());
      return;
    }
    assert(committeeManager_);
    committeeManager_->onMessage(msg, from.id());
  } else {
    Gossip msg{message};
    if (emitter == id_)
      return; // we gossiped it
    if (!updateGossip(gossipKey))
      return; // we already know the gossip
    // Shares can be but are currently not gossiped as everyone remains in a fully connected network
    // after DKG
    if (msg.hasSigShare()) {
      logger.trace("Node {} received gossip {} signature share from {}", id_, gossipKey, emitter);
      assert(committeeManager_);
      committeeManager_->onSignatureShare(msg.sig_share(), emitter);
    }
  }
}

template<class CryptoProtocol, class Derived>
bool Node<CryptoProtocol, Derived>::startHandShake(std::string nodeId) {
  if (nodeId == id_) {
    return false;
  }
  if (ongoingHandshakes_.find(nodeId) != ongoingHandshakes_.end()) {
    return true;
  }

  // Set handshake role
  int err = 0;
  int role = NOISE_ROLE_INITIATOR;
  if (nodeId > id_) {
    role = NOISE_ROLE_RESPONDER;
  }

  // Set handshake protocol
  const char *protocol = "Noise_IK_25519_AESGCM_SHA256";

  ongoingHandshakes_.insert({nodeId, nullptr});
  noise_handshakestate_new_by_name
          (&ongoingHandshakes_.at(nodeId), protocol, role);

  // Set own static private key
  if (noise_handshakestate_needs_local_keypair(ongoingHandshakes_.at(nodeId))) {
    // Get public/private keys
    std::vector<uint8_t> private_key;
    std::vector<uint8_t> public_key;
    private_key.resize(noise_dhstate_get_private_key_length(dhKeys_));
    public_key.resize(noise_dhstate_get_public_key_length(dhKeys_));
    err = noise_dhstate_get_keypair(dhKeys_, &private_key[0], noise_dhstate_get_private_key_length(dhKeys_),
                                    &public_key[0], noise_dhstate_get_public_key_length(dhKeys_));
    if (err != NOISE_ERROR_NONE) {
      return false;
    }

    auto temp_dh = noise_handshakestate_get_local_keypair_dh(ongoingHandshakes_.at(nodeId));
    err = noise_dhstate_set_keypair_private(temp_dh, &private_key[0],
                                            noise_dhstate_get_private_key_length(dhKeys_));
    if (err != NOISE_ERROR_NONE) {
      noise_perror("set private key", err);
      return false;
    }
  }

  // If role is initiator then set responder's static public key
  if (noise_handshakestate_needs_remote_public_key(ongoingHandshakes_.at(nodeId))) {
    assert(role == NOISE_ROLE_INITIATOR);
    auto temp_dh = noise_handshakestate_get_remote_public_key_dh(ongoingHandshakes_.at(nodeId));

    // Get and verify the node's DH key
    auto remotePublicKey = neighbourhood_.getNeighbour(nodeId)->signedDHPublicKey();
    {
      ECDSAKey verification_key;
      verification_key.setPublicKey(neighbourhood_.getNeighbour(nodeId)->ECDSAPublicKey());
      std::string publicKeyStr{remotePublicKey.first.begin(), remotePublicKey.first.end()};
      if (!verification_key.verify(SHA256(publicKeyStr), remotePublicKey.second)) {
        logger.warn("Node {} received DH key with invalid ecdsa signature from {}", id_, nodeId);
        return false;
      }
    }

    err = noise_dhstate_set_public_key(temp_dh, &remotePublicKey.first[0],
                                       noise_dhstate_get_public_key_length(dhKeys_));
    if (err != NOISE_ERROR_NONE) {
      noise_perror("set remote public key", err);
      return false;
    }
  }

  err = noise_handshakestate_start(ongoingHandshakes_.at(nodeId));
  if (err != NOISE_ERROR_NONE) {
    noise_perror("start handshake", err);
    return false;
  }

  // Start exchanging of handshake messages
  if (noise_handshakestate_get_action(ongoingHandshakes_.at(nodeId)) == NOISE_ACTION_WRITE_MESSAGE) {
    return sendNextHandshakeMessage(nodeId);
  }
  return true;
}

template<class CryptoProtocol, class Derived>
bool Node<CryptoProtocol, Derived>::sendNextHandshakeMessage(const std::string &nodeId) {
  NoiseBuffer mbuf;
  uint8_t message[MAX_MESSAGE_LEN + 2];
  noise_buffer_set_output(mbuf, message + 2, sizeof(message) - 2);
  int err = noise_handshakestate_write_message(ongoingHandshakes_.at(nodeId), &mbuf, nullptr);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("write handshake", err);
    return false;
  }
  // noise protocol assigns first two elements
  message[0] = (uint8_t) (mbuf.size >> 8);
  message[1] = (uint8_t) mbuf.size;

  fetch::consensus::pb::Direct msg;
  msg.set_committee_id(0);
  auto handshake_msg = msg.mutable_handshake();
  for (size_t i = 0; i < mbuf.size + 2; ++i) {
    handshake_msg->add_payload(message[i]);
  }
  sendDirect(msg, nodeId);
  logger.debug("Node {} send handshake message to node {}", id_, nodeId);

  if (noise_handshakestate_get_action(ongoingHandshakes_.at(nodeId)) != NOISE_ACTION_READ_MESSAGE) {
    logger.info("Node {} completed handshake with node {}", id_, nodeId);
    onCompleteHandshake(nodeId);
  }
  return true;
}

template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::onHandshake(const fetch::consensus::pb::Direct_NoiseMessage &handshakeMsg,
                                              const std::string &nodeId) {
  std::lock_guard<std::mutex> lock(handshakeMutex_);
  if (ongoingHandshakes_.find(nodeId) == ongoingHandshakes_.end()) {
    if (privateChannelCiphers_.find(nodeId) != privateChannelCiphers_.end()) {
      return;
    }
    bool check = startHandShake(nodeId);
    assert(check);
  }
  if (noise_handshakestate_get_action(ongoingHandshakes_.at(nodeId)) != NOISE_ACTION_READ_MESSAGE) {
    assert(false);
    return;
  }

  uint8_t message[MAX_MESSAGE_LEN + 2];
  for (auto i = 0; i < handshakeMsg.payload_size(); ++i) {
    message[i] = static_cast<uint8_t>(handshakeMsg.payload(i));
  }

  NoiseBuffer mbuf;
  noise_buffer_set_input(mbuf, message + 2, handshakeMsg.payload_size() - 2);
  int err = noise_handshakestate_read_message(ongoingHandshakes_.at(nodeId), &mbuf, nullptr);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("read handshake", err);
    return;
  }

  if (noise_handshakestate_get_action(ongoingHandshakes_.at(nodeId)) == NOISE_ACTION_WRITE_MESSAGE) {
    sendNextHandshakeMessage(nodeId);
  } else {
    logger.info("Node {} completed handshake with node {}", id_, nodeId);
    onCompleteHandshake(nodeId);
  }
}

template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::onCompleteHandshake(const std::string &nodeId) {
  assert(privateChannelCiphers_.find(nodeId) == privateChannelCiphers_.end());
  privateChannelCiphers_.insert({nodeId, {nullptr, nullptr}});
  int err = noise_handshakestate_split(ongoingHandshakes_.at(nodeId), &privateChannelCiphers_.at(nodeId).first,
                                       &privateChannelCiphers_.at(nodeId).second);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("split handshake", err);
    return;
  }
  // Delete handshake
  noise_handshakestate_free(ongoingHandshakes_.at(nodeId));
  ongoingHandshakes_.erase(nodeId);
  receivedHandshake();
}

template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::sendEncrypted(uint8_t message[MAX_MESSAGE_LEN + 2], size_t size,
                                                const std::string &receiverId, uint8_t committeeId) {
  // Have not completed handshake with receiver
  if (privateChannelCiphers_.find(receiverId) == privateChannelCiphers_.end()) {
    return;
  }
  logger.debug("Node {} sends encrypted message {} to {}", id_, message, receiverId);

  NoiseBuffer mbuf;
  noise_buffer_set_inout
  (mbuf, message + 2, size, MAX_MESSAGE_LEN);
  int err = noise_cipherstate_encrypt(privateChannelCiphers_.at(receiverId).first, &mbuf);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("write", err);
    return;
  }
  message[0] = (uint8_t) (mbuf.size >> 8);
  message[1] = (uint8_t) mbuf.size;

  // Pack into a noise message
  fetch::consensus::pb::Direct encrypted_msg;
  encrypted_msg.set_committee_id(committeeId);
  auto noise_msg = encrypted_msg.mutable_encrypted_cipher();
  for (size_t i = 0; i < mbuf.size + 2; ++i) {
    noise_msg->add_payload(message[i]);
  }
  sendDirect(encrypted_msg, receiverId);
}

template<class CryptoProtocol, class Derived>
bool Node<CryptoProtocol, Derived>::decryptCipher(const fetch::consensus::pb::Direct_NoiseMessage &encrypted,
                                                const std::string &senderId, uint8_t decrypted[MAX_MESSAGE_LEN + 2],
                                                size_t &size) {
  if (privateChannelCiphers_.find(senderId) == privateChannelCiphers_.end()) {
    return false;
  }
  for (auto i = 0; i < encrypted.payload_size(); ++i) {
    decrypted[i] = static_cast<uint8_t>(encrypted.payload(i));
  }

  // Decrypt the incoming message
  NoiseBuffer mbuf;
  noise_buffer_set_input(mbuf, decrypted + 2, encrypted.payload_size() - 2);
  int err = noise_cipherstate_decrypt(privateChannelCiphers_.at(senderId).second, &mbuf);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("read", err);
    return false;
  }

  size = mbuf.size;
  logger.debug("Node {} received encrypted message {} from {}", id_, decrypted, senderId);
  return true;
}

/**
 * Handler for broadcast messages
 *
 * @param message Serialised message
 * @param from Sender of the message
 */
template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::onBroadcast(const std::string &message, std::string from) {
  logger.trace("onBroadcast {} from {}", id_, from);
  assert(neighbourhood_.check(from));

  fetch::consensus::pb::Broadcast msg;
  msg.ParseFromString(message);
  auto payload = msg.payload_case();
  switch (payload) {
    case fetch::consensus::pb::Broadcast::kCommittee:
      assert(committeeManager_);
      committeeManager_->onNewCommittee(msg.committee(), from);
      break;
    case fetch::consensus::pb::Broadcast::kCoefficients:
      logger.trace("receive coefficients {} from {}", id_, from);
      assert(committeeManager_);
      committeeManager_->onNewCoefficients(msg.coefficients(), from);
      break;
    case fetch::consensus::pb::Broadcast::kComplaints:
      logger.trace("complaint {} from {}", id_, from);
      assert(committeeManager_);
      committeeManager_->onComplaints(msg.complaints(), from);
      break;
    case fetch::consensus::pb::Broadcast::kShares:
      assert(committeeManager_);
      committeeManager_->onExposedShares(msg.shares(), from);
      break;
    case fetch::consensus::pb::Broadcast::PAYLOAD_NOT_SET:
      logger.error("Connection::process cannot process payload {} from {}", payload, id_);
  }
}

/**
 * Call to start the DKG
 */
template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::beginDKG() {
  onNewNeighbour();
}

/**
 * Disconnect from all connections
 */
template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::disconnect() {
  derived().disconnect();
}

/**
 * Send a signature share for computing group signature
 *
 * @param message Message to be signed
 */
template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::sendSignatureShare() {
  assert(committeeManager_);
  committeeManager_->sendSignatureShare();
}

/**
 * Turn on threshold signing, which takes hash of previous group signature as
 * next message to be signed

 * @param t Number group signatures to compute before terminating
 */
template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::enableThresholdSigning(uint32_t t) {
  assert(committeeManager_);
  committeeManager_->enableThresholdSigning(t);
}

/**
 * Function used in tests to set the outputs of the DKG using trusted dealer

 * @param committee DKG members
 * @param output Struct containing group public key, private key and public key shares
 */
template<class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::setDkgOutput(const std::set<std::string> &committee,
                                               const typename CryptoProtocol::DkgOutput &output) {
  assert(committeeManager_);
  committeeManager_->setDkgOutput(committee, output);
}

template<class CryptoProtocol, class Derived>
std::string Node<CryptoProtocol, Derived>::ECDSAPublicKey() const {
  return ecdsaKey_.publicKey();
}

template<class CryptoProtocol, class Derived>
std::pair<std::vector<uint8_t>, ECDSAKey::ECDSASignature> Node<CryptoProtocol, Derived>::signedDHPublicKey() const {
  return signedDHKey_;
}

template <class CryptoProtocol, class Derived>
void Node<CryptoProtocol, Derived>::setSignMessages(bool sign) {
  signAllMessages_ = sign;
}
}
}
