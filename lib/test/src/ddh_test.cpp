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

#include "catch.hpp"
#include "crypto_sodium.hpp"
#include "ddh_dvrf.hpp"
#include "localnode.hpp"
#include "simplenode.hpp"
#include "test_builders.hpp"

using namespace fetch::consensus;

TEST_CASE("ddh_no_network", "[ddh][template]") {
  CryptoSodium::initCrypto();
  build_no_network<DdhDvrf<CryptoSodium>>();
}

TEST_CASE("ddh_local_node", "[local][ddh]") {
  CryptoSodium::initCrypto();
  build_local<LocalNode<DdhDvrf<CryptoSodium>>>(4, 2, 3);
}

TEST_CASE("ddh_simple_node", "[simple][ddh]") {
  CryptoSodium::initCrypto();
  build_local<SimpleNode<DdhDvrf<CryptoSodium>>>(4, 2, 3);
}

TEST_CASE("ddh_network_node", "[network][ddh]") {
  CryptoSodium::initCrypto();
  build_network<DdhDvrf<CryptoSodium>>(4, 2, 3);
}