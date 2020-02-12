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

#define CATCH_CONFIG_ENABLE_BENCHMARKING
#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file

#include "catch.hpp"
#include "ecdsa.hpp"
#include "networknode.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include "threadpool.hpp"

#include <iostream>
#include <chrono>

using namespace fetch::consensus;

int f(float val) {
  return int(val);
}

TEST_CASE("threadpool", "[threadpool]") {
  ThreadPool &pool = ThreadPool::getInstance(4); // optional parameter
  auto res_int = pool.enqueue([](int param) { return param * param; }, 42);
  auto res_float = pool.enqueue([](float param) { return param * param; }, 42.0);
  auto res_bool = pool.enqueue([](bool param) { return !param; }, true);
  auto res_f = pool.enqueue(f, 25.3);
  REQUIRE(res_int.get() == 1764);
  REQUIRE(res_float.get() == 1764.0);
  REQUIRE_FALSE(res_bool.get());
  REQUIRE(res_f.get() == 25);
}

TEST_CASE("sha256", "[sha]") {
  fetch::consensus::SHA256 sha256{"Hello world"};
  REQUIRE(sha256.toString() == "64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c");
}

TEST_CASE("sha512", "[sha]") {
  fetch::consensus::SHA512 sha512{"Hello World"};
  REQUIRE(sha512.toString() ==
          "3d58a719c6866b0214f96b0a67b37e51a91e233ce0be126a08f35fdf4c043c6126f40139bfbc338d44eb2a03de9f7bb8eff0ac260b3629811e389a5fbee8a894");
}

TEST_CASE("ecdsa", "[ecdsa]") {
  ECDSAKey key;
  key.generateKeys();
  std::vector<uint8_t> signature;

  ECDSAKey justPublicKey;
  justPublicKey.setPublicKey(key.publicKey());

  fetch::consensus::SHA256 message{"Hello World"};
  key.sign(message, signature);

  REQUIRE(key.verify(message, signature));
  REQUIRE(justPublicKey.verify(message, signature));
}

/*
TEST_CASE("local network node", "[network]") {
  IoContextPool pool{4};
  pool.run();

  DefaultObserver obs;
  NetworkNode<CryptoMCLPairing> node1{"Node1", obs, pool.getIoContext(), 1024};
  NetworkNode<CryptoMCLPairing> node2{"Node2", obs, pool.getIoContext(), 1025};
  NetworkNode<CryptoMCLPairing> node3{"Node3", obs, pool.getIoContext(), 1026};
  NetworkNode<CryptoMCLPairing> node4{"Node4", obs, pool.getIoContext(), 1027};
  node1.addNeighbour(node2);
  node1.addNeighbour(node3);
  node3.addNeighbour(node4);
  std::this_thread::sleep_for(std::chrono::seconds{1});
  pool.stop();
}
 */
