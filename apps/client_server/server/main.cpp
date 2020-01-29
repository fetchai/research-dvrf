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

#include "clara.hpp"
#include "server.hpp"
#include "scheduler.hpp"

using namespace fetch::consensus;

int main(int argc, char *argv[]) {
  bool showHelp{false};
  uint16_t serverPort{2025};
  uint32_t timeout{60};

  auto parser = clara::Help(showHelp)
                | clara::Opt(serverPort, "server port")["--port"]["-p"]("Unique port number for server. Default 1025")
                |
                clara::Opt(timeout, "server timeout")["--timeout"]["-t"]("Timeout in seconds for server. Default 60s");

  auto result = parser.parse(clara::Args(argc, argv));
  if (showHelp || argc == 1) {
    std::cout << parser << std::endl;
  } else {
    try {
      Scheduler scheduler{4};
      Server server{scheduler.getIoContext(), serverPort};

      std::this_thread::sleep_for(std::chrono::seconds(timeout));

      scheduler.stop();
    } catch (std::exception &e) {
      std::cerr << "Exception: " << e.what() << "\n";
    }
  }
  return 0;
}