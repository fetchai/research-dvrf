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

#include "crypto_mcl.hpp"
#include "crypto_relic.hpp"

#include "glow_dvrf.hpp"
#include "sha512.hpp"
#include "catch.hpp"

using namespace fetch::consensus;

TEMPLATE_TEST_CASE("glow_dvrf_functions", "[benchmark][glow]", CryptoMcl, CryptoRelic) {
  using CryptoType = TestType;
  using Drb = GlowDvrf<CryptoType>;
  using Signature = typename Drb::Signature;
  using Generator = typename Drb::Signature;
  using Proof = typename Drb::Proof;

  Drb::initCrypto();
  Generator generator;
  Drb::setGenerator(generator);

  {
    uint32_t committeeSize = 50;
    uint32_t threshold = 26;
    auto outputs = Drb::trustedDealer(committeeSize, threshold);

    BENCHMARK_ADVANCED("Partial Eval")(Catch::Benchmark::Chronometer meter) {
        auto i = static_cast<uint32_t>(rand() % committeeSize);
        std::string message{SHA512("hello" + std::to_string(rand() * rand())).toString()};
        meter.measure([&message, &outputs, &generator, i] {
          auto sig = Drb::sign(message, outputs[i].privateKey);
          auto pi = Drb::proof(generator, message, outputs[i].publicKeyShares[i], sig,
                               outputs[i].privateKey);
          return std::make_pair(sig, pi);
        });
      };
  }

  {
    {
      uint32_t committeeSize = 50;
      uint32_t threshold = 26;
      auto outputs = Drb::trustedDealer(committeeSize, threshold);

      BENCHMARK_ADVANCED("Combine l_50")(Catch::Benchmark::Chronometer meter) {
          std::string message{SHA512("hello" + std::to_string(rand() * rand())).toString()};
          std::set<uint32_t> members;
          while (members.size() < threshold) {
            members.insert(rand() % committeeSize);
          }

          std::unordered_map<uint32_t, Signature> signature_shares;
          std::unordered_map<uint32_t, Proof> proofs;
          // Compute signatures and verify
          for (auto const &mem : members) {
            auto sig = Drb::sign(message, outputs[mem].privateKey);
            auto pi = Drb::proof(generator, message, outputs[mem].publicKeyShares[mem], sig,
                                 outputs[mem].privateKey);
            signature_shares.insert({mem, sig});
            proofs.insert({mem, pi});
          }

          // Measure time to verify and combine signatures
          meter.measure([&signature_shares, &outputs, &message, &generator, &proofs] {
            for (auto const &mem : signature_shares) {
              bool verify = Drb::verify(outputs[mem.first].publicKeyShares[mem.first], message, mem.second,
                                        generator, proofs[mem.first]);
              if (!verify) {
                std::cerr << "Verification failed in Combine. Abort." << std::endl;
                return Signature();
              }
            }
            return Drb::lagrangeInterpolation(signature_shares);
          });
        };
    }

    {
      uint32_t committeeSize = 100;
      uint32_t threshold = 51;
      auto outputs = Drb::trustedDealer(committeeSize, threshold);

      BENCHMARK_ADVANCED("Combine l_100")(Catch::Benchmark::Chronometer meter) {
          std::string message{SHA512("hello" + std::to_string(rand() * rand())).toString()};
          std::set<uint32_t> members;
          while (members.size() < threshold) {
            members.insert(rand() % committeeSize);
          }

          std::unordered_map<uint32_t, Signature> signature_shares;
          std::unordered_map<uint32_t, Proof> proofs;
          // Compute signatures and verify
          for (auto const &mem : members) {
            auto sig = Drb::sign(message, outputs[mem].privateKey);
            auto pi = Drb::proof(generator, message, outputs[mem].publicKeyShares[mem], sig,
                                 outputs[mem].privateKey);
            signature_shares.insert({mem, sig});
            proofs.insert({mem, pi});
          }

          // Measure time to verify and combine signatures
          meter.measure([&signature_shares, &outputs, &message, &generator, &proofs] {
            for (auto const &mem : signature_shares) {
              bool verify = Drb::verify(outputs[mem.first].publicKeyShares[mem.first], message, mem.second,
                                        generator, proofs[mem.first]);
              if (!verify) {
                std::cerr << "Verification failed in Combine. Abort." << std::endl;
                return Signature();
              }
            }
            return Drb::lagrangeInterpolation(signature_shares);
          });
        };
    }

    {
      uint32_t committeeSize = 200;
      uint32_t threshold = 101;
      auto outputs = Drb::trustedDealer(committeeSize, threshold);

      BENCHMARK_ADVANCED("Combine l_200")(Catch::Benchmark::Chronometer meter) {
          std::string message{SHA512("hello" + std::to_string(rand() * rand())).toString()};
          std::set<uint32_t> members;
          while (members.size() < threshold) {
            members.insert(rand() % committeeSize);
          }

          std::unordered_map<uint32_t, Signature> signature_shares;
          std::unordered_map<uint32_t, Proof> proofs;
          // Compute signatures and verify
          for (auto const &mem : members) {
            auto sig = Drb::sign(message, outputs[mem].privateKey);
            auto pi = Drb::proof(generator, message, outputs[mem].publicKeyShares[mem], sig,
                                 outputs[mem].privateKey);
            signature_shares.insert({mem, sig});
            proofs.insert({mem, pi});
          }

          // Measure time to verify and combine signatures
          meter.measure([&signature_shares, &outputs, &message, &generator, &proofs] {
            for (auto const &mem : signature_shares) {
              bool verify = Drb::verify(outputs[mem.first].publicKeyShares[mem.first], message, mem.second,
                                        generator, proofs[mem.first]);
              if (!verify) {
                std::cerr << "Verification failed in Combine. Abort." << std::endl;
                return Signature();
              }
            }
            return Drb::lagrangeInterpolation(signature_shares);
          });
        };
    }
  }
}

TEMPLATE_TEST_CASE("glow_other_functions", "[benchmark][glow][!hide]", CryptoMcl, CryptoRelic) {
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

  {
    uint32_t committeeSize = 50;
    uint32_t threshold = 26;
    auto outputs = Drb::trustedDealer(committeeSize, threshold);

    auto groupPublicKey = outputs[0].groupPublicKey;

    BENCHMARK_ADVANCED("Verify")(Catch::Benchmark::Chronometer meter) {
        std::string message{SHA512("hello" + std::to_string(rand() * rand())).toString()};
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

        meter.measure([&groupPublicKey, &message, &groupSig, &generator2] {
          return Drb::verify(groupPublicKey, message, groupSig, generator2);
        });
      };
  }

  {
    {
      uint32_t committeeSize = 50;
      uint32_t threshold = 26;
      auto outputs = Drb::trustedDealer(committeeSize, threshold);

      BENCHMARK_ADVANCED("Lagrange Interpolation l_50")(Catch::Benchmark::Chronometer meter) {
          std::string message{SHA512("hello" + std::to_string(rand() * rand())).toString()};
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
          meter.measure([&signature_shares] {
            return Drb::lagrangeInterpolation(signature_shares);
          });
        };
    }

    {
      uint32_t committeeSize = 100;
      uint32_t threshold = 51;
      auto outputs = Drb::trustedDealer(committeeSize, threshold);

      BENCHMARK_ADVANCED("Lagrange Interpolation l_100")(Catch::Benchmark::Chronometer meter) {
          std::string message{SHA512("hello" + std::to_string(rand() * rand())).toString()};
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
          meter.measure([&signature_shares] {
            return Drb::lagrangeInterpolation(signature_shares);
          });
        };
    }

    {
      uint32_t committeeSize = 200;
      uint32_t threshold = 101;
      auto outputs = Drb::trustedDealer(committeeSize, threshold);

      BENCHMARK_ADVANCED("Lagrange Interpolation l_200")(Catch::Benchmark::Chronometer meter) {
          std::string message{SHA512("hello" + std::to_string(rand() * rand())).toString()};
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
          meter.measure([&signature_shares] {
            return Drb::lagrangeInterpolation(signature_shares);
          });
        };
    }
  }
}