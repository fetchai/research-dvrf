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

#include "app_builds.hpp"
#include "crypto_mcl.hpp"
#include "crypto_sodium.hpp"
#include "crypto_relic.hpp"
#include "dfinity_dvrf.hpp"
#include "glow_dvrf.hpp"
#include "ddh_dvrf.hpp"
#include "clara.hpp"

using namespace fetch::consensus;

int main(int argc, char *argv[]) {
  bool showHelp{false};
  uint16_t port{0};
  uint16_t serverPort{2025};
  uint32_t nbNodes{4};
  uint32_t threshold{3};
  uint32_t nbRounds{4};
  uint32_t networkResolution{30};
  bool signMessages{false};
  uint32_t cryptoLib{1};

  auto parser = clara::Help(showHelp)
                | clara::Arg(port, "port")("Unique port number for node")
                | clara::Opt(serverPort, "server port")["--serverPort"]["--v"](
          "Unique port number for server. Default 1025")
                | clara::Opt(nbRounds, "rounds")["--rounds"]["-r"]("Number of rounds of threshold signing. Default 4")
                | clara::Opt(threshold, "threshold")["--threshold"]["-T"]("Threshold for signing. Default 3")
                | clara::Opt(nbNodes, "nodes")["--nodes"]["-N"]("Number of nodes. Default 4")
                | clara::Opt(signMessages, "sign")["--sign"]["-s"]("Sign all messages. Default false")
                | clara::Opt(cryptoLib, "protocol")["--protocol"]["-p"](
          "1 = Dfinity-mcl, 2 = Dfinity-relic, 3 = DDH-libsodium, 4 = GLOW-mcl, 5 = GLOW-relic Default 1.")
                | clara::Opt(networkResolution, "connection wait")["--wait"]["-w"](
          "Number of seconds to wait for connections to resolve. Default 30");

  auto result = parser.parse(clara::Args(argc, argv));
  if (showHelp || argc == 1) {
    std::cout << parser << std::endl;
  } else {
    try {
      Scheduler scheduler{4};

      DKGEventObserver obs;
      std::unique_ptr<fetch::consensus::AbstractDkgNode> node;
      switch (cryptoLib) {
        case 1:
          node = build<DfinityDvrf<CryptoMcl>>(port, serverPort, nbNodes, threshold, obs, scheduler, signMessages);
          break;
        case 2:
          node = build<DfinityDvrf<CryptoRelic>>(port, serverPort, nbNodes, threshold, obs, scheduler, signMessages);
          break;
        case 3:
          node = build<DdhDvrf<CryptoSodium>>(port, serverPort, nbNodes, threshold, obs, scheduler, signMessages);
          break;
        case 4:
          node = build<GlowDvrf<CryptoMcl>>(port, serverPort, nbNodes, threshold, obs, scheduler, signMessages);
          break;
        case 5:
          node = build<GlowDvrf<CryptoRelic>>(port, serverPort, nbNodes, threshold, obs, scheduler, signMessages);
          break;
        default:
          node = build<DfinityDvrf<CryptoMcl>>(port, serverPort, nbNodes, threshold, obs, scheduler, signMessages);
          break;
      }
      obs.waitForConnections();

      // Wait for connections to resolve
      std::cerr << "****Wait " << networkResolution << " seconds for connections to resolve.****" << std::endl;
      std::this_thread::sleep_for(std::chrono::seconds{networkResolution});

      std::cerr << "****Begin DKG.****" << std::endl;
      node->beginDKG();
      obs.waitForDKG();

      // Start beacon signing
      std::cerr << "****Begin threshold signing for " << nbRounds << " rounds.****" << std::endl;
      node->enableThresholdSigning(nbRounds);
      node->sendSignatureShare();
      obs.waitForSignedMessage();

      std::this_thread::sleep_for(std::chrono::seconds{1});

      std::cerr << "****Finished. Disconnect.****" << std::endl;
      node->disconnect();
      scheduler.stop();
    } catch (std::exception &e) {
      std::cerr << "Exception: " << e.what() << "\n";
    }
  }
  return 0;
}