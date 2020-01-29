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
#include "localnode.hpp"
#include "networknode.hpp"
#include "crypto_mcl.hpp"
#include "dfinity_dvrf.hpp"
#include "graph.hpp"
#include "clara.hpp"

using namespace fetch::consensus;
using NetworkNodeCrypto = NetworkNode<DfinityDvrf<CryptoMcl>>;
using LocalNodeCrypto = LocalNode<DfinityDvrf<CryptoMcl>>;

fetch::consensus::Logger logger = fetch::consensus::Logger("main");

fetch::consensus::Graph graph(const std::string &method, uint32_t nbNodes) {
  if (method == "small_world")
    return fetch::consensus::Graph::small_world(nbNodes, 2, 1.);
  if (method == "block")
    return fetch::consensus::Graph::block_model(nbNodes, static_cast<uint32_t>(std::sqrt(nbNodes) + 0.5));
  std::cerr << "Unknown method: " << method << std::endl;
  std::exit(1);
}

bool is_complete(const std::vector<std::unique_ptr<fetch::consensus::AbstractNode>> &nodes) {
  size_t total = nodes.size();
  for (const auto &n : nodes)
    if (n->networkSize() != total) {
      return false;
    }
  return true;
}

class ConnectionObserver : public EventObserver {
  std::condition_variable cv_;
  std::mutex m_;
  std::condition_variable conditionVariable_;
  std::unordered_map<std::string, std::set<std::string>> connections_set_;
  std::unordered_map<std::string, uint32_t> connections_;
  std::unordered_set<std::string> fully_connected_;
public:
  ConnectionObserver() = default;

  void notifyRBCDeliver(const tag_type &, uint32_t, uint32_t) override {}

  void notifyCommitteeSync(const std::string &) override {}

  void notifyDKGCompleted(const std::string &, const Duration &, const std::string &) override {}

  void
  notifyBroadcastSignature(const std::string &, std::chrono::time_point<std::chrono::high_resolution_clock>) override {}

  void notifySignedMessage(const std::string &, std::chrono::time_point<std::chrono::high_resolution_clock>) override {}

  void notifyGroupSignature(const std::string &, const std::string &) override {}

  void addConnection(const std::string &node, uint32_t nbConnections) {
    connections_[node] = nbConnections;
  }

  void waitForConnection() {
    std::unique_lock<std::mutex> mlock(m_);
    while (fully_connected_.size() < connections_.size())
      conditionVariable_.wait(mlock);
    std::cerr << "All connected.\n";
  }

  void notifyNewConnection(const std::string &id, const std::string &to) override {
    std::unique_lock<std::mutex> mlock(m_);
    auto &dest = connections_set_[id];
    auto iter = dest.find(to);
    assert(iter == dest.end());
    dest.insert(to);
    std::string msg = "Debug: Node " + id + " exp " + std::to_string(connections_[id]) + " rec " +
                      std::to_string(connections_set_[id].size()) + "\n";
    std::cerr << msg;
    if (dest.size() == connections_[id]) {
      fully_connected_.insert(id);
      std::cerr << "Node " << id << " is fully connected\n";
    }
    mlock.unlock();
    conditionVariable_.notify_one();
  };
};

std::vector<std::unique_ptr<fetch::consensus::AbstractNode>>
network(const fetch::consensus::Graph &g, bool networked, fetch::consensus::Scheduler &scheduler,
        ConnectionObserver &obs) {
  std::vector<std::unique_ptr<fetch::consensus::AbstractNode>> ret;
  if (networked) {
    for (uint32_t i = 0; i < g.num_vertices(); ++i) {
      const std::string name = "Node" + std::to_string(i);
      ret.push_back(std::unique_ptr<fetch::consensus::AbstractNode>{
              new NetworkNodeCrypto{name, obs, scheduler.getIoContext(),
                                    static_cast<uint16_t>(1024 + i)}});
      obs.addConnection(name, g.num_edges(i));
    }
    g.scan_edges([&ret](const fetch::consensus::Vertex &v1, const fetch::consensus::Vertex &v2) {
      dynamic_cast<NetworkNodeCrypto *>(ret[v1].get())->
              addNeighbour(*(dynamic_cast<NetworkNodeCrypto *>(ret[v2].get())));
    });
  } else {
    for (uint32_t i = 0; i < g.num_vertices(); ++i) {
      const std::string name = "Node" + std::to_string(i);
      ret.push_back(std::unique_ptr<fetch::consensus::AbstractNode>{
              new LocalNodeCrypto{name, obs, scheduler}});
      obs.addConnection(name, g.num_edges(i));
    }
    g.scan_edges([&ret](const fetch::consensus::Vertex &v1, const fetch::consensus::Vertex &v2) {
      dynamic_cast<LocalNodeCrypto *>(ret[v1].get())->
              addNeighbour(*(dynamic_cast<LocalNodeCrypto *>(ret[v2].get())));
    });
    while (!is_complete(ret)) {
      std::this_thread::sleep_for(std::chrono::seconds{1});
    }
  }
  return ret;
}

int main(int argc, char *argv[]) {
  spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [thread %t] [%n] [%l] %v");
  spdlog::set_level(spdlog::level::level_enum::trace);
  bool showHelp{false};
  bool networked{false};
  uint32_t threads{4};
  uint32_t nbNodes{100};
  uint32_t threshold{51};
  uint32_t nbRounds{4};
  std::string method{"small_world"};

  auto parser = clara::Help(showHelp)
                | clara::Opt(threads, "threads")["--threads"]["-t"]("Number of threads for the server. Default 4.")
                | clara::Opt(networked, "networked")["--networked"]["-n"]("Networked nodes. Default false.")
                | clara::Opt(nbRounds, "rounds")["--rounds"]["-r"]("Number of rounds. Default 2")
                | clara::Opt(method, "method")["--method"]["-m"]("Method of generation: small_world (default), block")
                | clara::Opt(threshold, "threshold")["--threshold"]["-T"]("Threshold: default 51")
                | clara::Opt(nbNodes, "nodes")["--nodes"]["-N"]("Number of nodes. Default 100");

  auto result = parser.parse(clara::Args(argc, argv));
  if (showHelp || argc == 1) {
    std::cout << parser << std::endl;
  } else {
    try {
      std::transform(method.begin(), method.end(), method.begin(), ::tolower);
      fetch::consensus::Graph g = graph(method, nbNodes);
      auto roots = g.roots();
      if (roots.size() > 1) {
        for (size_t i = 0; i < roots.size() - 1; ++i) {
          g.add_edge(roots[i], roots[i + 1]);
        }
      }
      fetch::consensus::Scheduler scheduler{threads};
      ConnectionObserver obs;
      {
        auto nodes = network(g, networked, scheduler, obs);
        obs.waitForConnection();
        std::this_thread::sleep_for(std::chrono::seconds(5));
      }
      scheduler.stop();
    } catch (std::exception &e) {
      std::cerr << "Exception: " << e.what() << "\n";
    }
  }
  return 0;
}
