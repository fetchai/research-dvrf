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

#include "glow_dvrf.hpp"
#include "crypto_mcl.hpp"
#include "crypto_relic.hpp"
#include "localnode.hpp"
#include "simplenode.hpp"
#include "test_builders.hpp"
#include "catch.hpp"

using namespace fetch::consensus;

TEMPLATE_TEST_CASE("glow_check_group_sig", "[glow]", CryptoMcl, CryptoRelic) {
  using CryptoType = TestType;
  using Drb = GlowDvrf<CryptoType>;
  using Signature = typename Drb::Signature;
  using Generator = typename Drb::Signature;
  using Generator2 = typename Drb::GroupPublicKey;

  Drb::initCrypto();
  Generator generator;
  Generator2 generator2;
  Drb::setGenerator(generator);
  Drb::setGenerator(generator2);

  uint32_t committeeSize = 50;
  uint32_t threshold = 26;
  auto outputs = Drb::trustedDealer(committeeSize, threshold);

  auto groupPublicKey = outputs[0].groupPublicKey;

  std::string message{SHA256("hello" + std::to_string(rand() * rand())).toString()};
  std::set<uint32_t> members;
  while (members.size() < threshold) {
    members.insert(rand() % committeeSize);
  }

  std::unordered_map<uint32_t, Signature> signature_shares;
  // Compute signatures and verify
  for (auto const &mem : members) {
    auto sig = Drb::sign(message, outputs[mem].privateKey);
    signature_shares.insert({mem, sig});
  }

  auto groupSig = Drb::lagrangeInterpolation(signature_shares);

  REQUIRE(Drb::verify(groupPublicKey, message, groupSig, generator2));
}

TEMPLATE_TEST_CASE("glow_no_network", "[glow]", CryptoMcl, CryptoRelic) {
  TestType::initCrypto();
  build_no_network<GlowDvrf<TestType>>();
}

TEMPLATE_TEST_CASE("glow_local_node", "[local][glow]", CryptoMcl, CryptoRelic) {
  TestType::initCrypto();
  build_local<LocalNode<GlowDvrf<TestType>>>(4, 2, 3);
}

TEMPLATE_TEST_CASE("glow_simple_node", "[simple][glow]", CryptoMcl, CryptoRelic) {
  TestType::initCrypto();
  build_local<SimpleNode<GlowDvrf<TestType>>>(4, 2, 3);
}

TEMPLATE_TEST_CASE("glow_network_node", "[network][glow]", CryptoMcl, CryptoRelic) {
  TestType::initCrypto();
  build_network<GlowDvrf<TestType>>(4, 2, 3);
}