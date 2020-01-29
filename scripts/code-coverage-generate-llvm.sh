#!/bin/bash -e
set -e

if [ $# -ne 1 ]; then
echo -e "\033[0;31m[!] Usage: ./scripts/code-coverage-generate-llvm.sh <SRC_ROOT>  \033[0m"
exit 1
fi

#
export SRC_RT=$(cd $1 && pwd)

#
cd ${SRC_RT} && mkdir -p build-coverage && cd build-coverage && rm ../build-coverage/* -rf

# Generate code coverage, steps

# 1. configure compiler to build with coverage flags
export CC=/usr/bin/clang
export CXX=/usr/bin/clang++
cmake ${SRC_RT} -DENABLE_COVERAGE_LLVM=ON 

# 2. compile and run the instrumented program to generate a raw profile 
make -j && LLVM_PROFILE_FILE="test_coverage.profraw" make test 

# 3. index raw profiles of executed binaries (tests ran by make test)
llvm-profdata merge --sparse ./lib/test/test_coverage.profraw -o test_coverage.profdata 

# 5. generate html visualization of the indexed profiles for excuted binaries
# to exclude 3rd party code: https://llvm.org/docs/CommandGuide/llvm-cov.html#llvm-cov-show
mkdir coverage && \
llvm-cov show -Xdemangler c++filt -instr-profile=test_coverage.profdata -format="html" ./lib/test/consensusTest -o coverage/

#
if [ $? -eq 0 ]; then
    export COVERAGE_HTML_INDEX="${SRC_RT}/build-coverage/coverage/index.html"
    echo -e "\033[0;32m[.] html code coverage: ${COVERAGE_HTML_INDEX}  \033[0m"
fi


