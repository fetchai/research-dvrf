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

#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <random>
#include <limits>
#include <cassert>
#include <iostream>

namespace fetch {
namespace consensus {
using Vertex = uint32_t;

uint32_t choose_with_exclusion(uint32_t max, uint32_t exclude, uint32_t seed = 1) {
  static std::minstd_rand gen2{seed};
  std::uniform_int_distribution<uint32_t> random_index{0, max - 1};
  uint32_t index{random_index(gen2)};

  while (index == exclude) {
    index = random_index(gen2);
  }
  return index;
}

class Graph {
  struct Edges {
    Vertex parent_;
    std::unordered_set<Vertex> neighbours_;

    Edges() : parent_{std::numeric_limits<Vertex>::max()} {}
  };

  std::unordered_map<Vertex, Edges> vertices_;
  uint32_t nb_edges_;

  std::unordered_map<Vertex, Edges>::iterator root(Vertex v) {
    auto iter = vertices_.find(v);
    assert(iter != vertices_.end());
    while (iter->second.parent_ != std::numeric_limits<Vertex>::max()) {
      iter = vertices_.find(iter->second.parent_);
      assert(iter != vertices_.end());
    }

    return iter;
  }

  void quick_union(Vertex v1, Vertex v2) {
    auto iter1 = root(v1);
    auto iter2 = root(v2);
    if (iter1 != iter2) {
      iter1->second.parent_ = iter2->first;
    }
  }

public:
  size_t num_vertices() const { return vertices_.size(); }

  uint32_t num_edges() const { return nb_edges_; }

  uint32_t num_edges(const Vertex &v) const {
    const auto &iter = vertices_.find(v);
    assert(iter != vertices_.end());
    return iter->second.neighbours_.size();
  }

  bool add_edge(Vertex v1, Vertex v2) {
    const auto &iter = vertices_.find(v1);
    if (iter != vertices_.end()) {
      if (iter->second.neighbours_.find(v2) != iter->second.neighbours_.end())
        return false; // already inserted
      iter->second.neighbours_.insert(v2);
    } else {
      vertices_[v1].neighbours_.insert(v2);
    }
    vertices_[v2].neighbours_.insert(v1);
    quick_union(v1, v2);
    ++nb_edges_;
    return true;
  }

  std::vector<Vertex> roots() const {
    std::vector<Vertex> res;
    for (const auto &v : vertices_) {
      if (v.second.parent_ == std::numeric_limits<Vertex>::max())
        res.push_back(v.first);
    }
    return res;
  }

  void scan_edges(std::function<void(Vertex, Vertex)> f) const {
    for (const auto &v : vertices_) {
      for (const auto &e : v.second.neighbours_) {
        f(v.first, e);
      }
    }
  }

  std::string to_graphviz() const {
    std::string res = "graph {\n";
    for (const auto &v : vertices_) {
      res += "  " + std::to_string(v.first) + " -- { ";
      for (const auto &e : v.second.neighbours_) {
        if (e > v.first)
          res += std::to_string(e) + " ";
      }
      res += "};\n";
    }
    res += "}\n";
    return res;
  }

  static Graph block_model(uint32_t num_vertices, uint32_t communities, float edgeM_diag = 0.1,
                           float edgeM_off_diag = 0.03, uint32_t seed = 1) {
    Graph res;
    std::minstd_rand gen2{seed};
    uint32_t comm_size = (num_vertices / communities);

    for (uint32_t i = 0; i < num_vertices - 1; ++i) {
      for (uint32_t j = i + 1; j < num_vertices; ++j) {
        std::bernoulli_distribution prob((i / comm_size) == (j / comm_size) ? edgeM_diag : edgeM_off_diag);
        if (prob(gen2)) {
          res.add_edge(i, j);
        }
      }
    }
    return res;
  }

  static Graph small_world(uint32_t num_vertices, uint32_t num_neighbours, float prop_rewiring, uint32_t seed = 1) {
    Graph res;
    std::bernoulli_distribution q_rewire{prop_rewiring};
    std::minstd_rand gen2{seed};

    for (uint32_t i = 0; i < num_vertices - 1; ++i) {
      for (uint32_t ik = i + 1; ik < i + num_neighbours + 1; ++ik) {
        res.add_edge(i, q_rewire(gen2) ? choose_with_exclusion(num_vertices, i) : (ik % num_vertices));
      }
    }
    return res;
  }
};
}
}

