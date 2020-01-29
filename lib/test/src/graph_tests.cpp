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
#include <fstream>

#include "graph.hpp"

using namespace fetch::consensus;

TEST_CASE("Add edge", "[graph]") {
  Graph g{};
  for (int i = 0; i < 3; ++i) {
    g.add_edge(i, i + 1);
  }
  REQUIRE(g.num_edges() == 3);
  REQUIRE(g.num_vertices() == 4);
  uint32_t count = 0;
  g.scan_edges([&count](Vertex, Vertex) {
    ++count;
  });
  REQUIRE(count == 6);
}

TEST_CASE("block model", "[graph]") {
  Graph g = Graph::block_model(20, 2);
  {
    std::ofstream out{"block_model.dot"};
    out << g.to_graphviz();
    out.close();
  }
  auto roots = g.roots();
  if (roots.size() > 1) {
    for (size_t i = 0; i < roots.size() - 1; ++i) {
      g.add_edge(roots[i], roots[i + 1]);
    }
  }
  REQUIRE(g.roots().size() == 1);
  {
    std::ofstream out{"block_model2.dot"};
    out << g.to_graphviz();
    out.close();
  }
}

TEST_CASE("small world", "[graph]") {
  Graph g = Graph::small_world(20, 3, 0);
  auto roots = g.roots();
  REQUIRE(g.roots().size() == 1);
  {
    std::ofstream out{"small_world.dot"};
    out << g.to_graphviz();
    out.close();
  }
}

TEST_CASE("small world2", "[graph]") {
  Graph g = Graph::small_world(20, 3, 1);
  auto roots = g.roots();
  REQUIRE(g.roots().size() == 1);
  {
    std::ofstream out{"small_world2.dot"};
    out << g.to_graphviz();
    out.close();
  }
}

TEST_CASE("roots", "[graph]") {
  Graph g{};
  REQUIRE(g.roots().size() == 0);
  g.add_edge(0, 1);
  REQUIRE(g.roots().size() == 1);
  g.add_edge(2, 3);
  REQUIRE(g.roots().size() == 2);
  g.add_edge(1, 2);
  REQUIRE(g.roots().size() == 1);
}
