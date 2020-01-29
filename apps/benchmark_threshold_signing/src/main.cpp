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

#include <iostream>
#include "app_builds.hpp"
#include "crypto_mcl.hpp"
#include "crypto_relic.hpp"
#include "crypto_sodium.hpp"
#include "dfinity_dvrf.hpp"
#include "glow_dvrf.hpp"
#include "ddh_dvrf.hpp"
#include "clara.hpp"

using namespace fetch::consensus;

int main(int argc, char *argv[]) {
  spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [thread %t] [%n] [%l] %v");
  spdlog::set_level(spdlog::level::level_enum::warn);
  bool showHelp{false};
  double latency{0};
  bool networked{false};
  uint32_t threads{8};
  uint32_t nbNodes{10};
  uint32_t threshold{6};
  uint32_t nbRounds{4};
  bool signMessages{false};
  uint32_t cryptoLib{1};

  auto parser = clara::Help(showHelp)
                | clara::Opt(threads, "threads")["--threads"]["-t"]("Number of threads for the server. Default 8.")
                | clara::Opt(networked, "networked")["--networked"]["-n"]("Networked nodes. Default false.")
                | clara::Opt(latency, "latency")["--latency"]["-l"]("Latency in ms. Default 0 (Ethereum = 120).")
                | clara::Opt(nbRounds, "rounds")["--rounds"]["-r"]("Number of rounds of threshold signing. Default 4")
                | clara::Opt(threshold, "threshold")["--threshold"]["-T"]("Threshold for signing. Default 6")
                | clara::Opt(nbNodes, "nodes")["--nodes"]["-N"]("Number of nodes. Default 10")
                | clara::Opt(signMessages, "sign")["--sign"]["-s"]("Sign all messages. Default false")
                | clara::Opt(cryptoLib, "protocol")["--protocol"]["-p"](
          "1 = Dfinity-mcl, 2 = Dfinity-relic, 3 = DDH-libsodium, 4 = GLOW-mcl, 5 = GLOW-relic Default 1.");

  auto result = parser.parse(clara::Args(argc, argv));
  if (showHelp || argc == 1) {
    std::cout << parser << std::endl;
  } else {
    try {
      fetch::consensus::Scheduler scheduler{threads};
      DKGEventObserver obs{nbNodes};
      std::vector<std::unique_ptr<fetch::consensus::AbstractDkgNode>> nodes;
      switch (cryptoLib) {
        case 1:
          nodes = build<DfinityDvrf<CryptoMcl>>(networked, latency, obs, nbNodes, threshold, scheduler, signMessages);
          break;
        case 2:
          nodes = build<DfinityDvrf<CryptoRelic>>(networked, latency, obs, nbNodes, threshold, scheduler, signMessages);
          break;
        case 3:
          nodes = build<DdhDvrf<CryptoSodium>>(networked, latency, obs, nbNodes, threshold, scheduler, signMessages);
          break;
        case 4:
          nodes = build<GlowDvrf<CryptoMcl>>(networked, latency, obs, nbNodes, threshold, scheduler,
                                                   signMessages);
          break;
        case 5:
          nodes = build<GlowDvrf<CryptoRelic>>(networked, latency, obs, nbNodes, threshold, scheduler,
                                                     signMessages);
          break;
        default:
          nodes = build<DfinityDvrf<CryptoMcl>>(networked, latency, obs, nbNodes, threshold, scheduler, signMessages);
      }
      auto start = std::chrono::high_resolution_clock::now();

      // Enable threshold signing
      for (uint32_t iv = 0; iv < nbNodes; ++iv) {
        nodes[iv]->enableThresholdSigning(nbRounds);
      }
      for (uint32_t iv = 0; iv < nbNodes; ++iv) {
        nodes[iv]->sendSignatureShare();
      }
      auto sign = obs.waitForSignedMessage(nbRounds);

      auto end = std::chrono::high_resolution_clock::now();
      auto total = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
      std::cout << "Total time " << total << "ms" << std::endl;
      std::cout << "Average unit time/round " << sign << "ms" << std::endl;
      std::cout << std::endl;
      assert(true);
      if (networked) {
        std::this_thread::sleep_for(std::chrono::seconds{10});
        for (auto &n : nodes)
          n->disconnect();
      }
      scheduler.stop();
    } catch (std::exception &e) {
      std::cerr << "Exception: " << e.what() << "\n";
    }
  }
  return 0;
}
