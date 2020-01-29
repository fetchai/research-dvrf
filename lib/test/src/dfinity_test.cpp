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

#include "dfinity_dvrf.hpp"
#include "crypto_mcl.hpp"
#include "crypto_relic.hpp"
#include "catch.hpp"
#include "localnode.hpp"
#include "simplenode.hpp"
#include "test_builders.hpp"

using namespace fetch::consensus;

TEMPLATE_TEST_CASE("dfinity_no_network", "[dfinity][template]", CryptoRelic, CryptoMcl) {
  TestType::initCrypto();
  build_no_network<DfinityDvrf<TestType>>();
}

TEMPLATE_TEST_CASE("dfinity_local_node", "[local][dfinity][template]", CryptoMcl, CryptoRelic) {
  TestType::initCrypto();
  build_local<LocalNode<DfinityDvrf<TestType>>>(4, 2, 3);
}

TEMPLATE_TEST_CASE("dfinity_network_node", "[network][dfinity][template]", CryptoMcl, CryptoRelic) {
  TestType::initCrypto();
  build_network<DfinityDvrf<TestType>>(4, 2, 3);
}

TEMPLATE_TEST_CASE("dfinity_simple_node", "[simple][dfinity][template]", CryptoMcl, CryptoRelic) {
  TestType::initCrypto();
  build_local<SimpleNode<DfinityDvrf<TestType>>>(4, 2, 3);
}