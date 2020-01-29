#!/bin/bash -e
set -e
# TOFIX exit script if a command fails

if [ $# -ne 1 ]; then
echo -e "\033[0;31m[!] Usage: ./scripts/code-coverage-generate-gcov.sh <SRC_ROOT>  \033[0m"
exit 1
fi

#
export SRC_RT=$(cd $1 && pwd)

#
cd ${SRC_RT} && mkdir -p build-coverage && cd build-coverage && rm ../build-coverage/* -rf

# Generate code coverage, steps
# 1. configure compiler to build with coverage flas
export CC=/usr/bin/gcc
export CXX=/usr/bin/g++
cmake ${SRC_RT} -DENABLE_COVERAGE=ON 
# 2. compiler will generate *.gcno files for each compiled object
# 3. running tests will generate *.gcda for each compiled object
#    excuted partially or entirely by tests
make -j && make test 

# 4. generate coverage information using lcov (that uses gcov)
mkdir coverage && cd coverage
lcov -c  --directory $(cd .. && pwd) --output-file test_coverage.info
# 5. generate html visualization of stats produced by lcov
genhtml test_coverage.info --output-directory html

#
if [ $? -eq 0 ]; then
    export COVERAGE_HTML_INDEX="${SRC_RT}/build-coverage/coverage/html/index.html"
    echo -e "\033[0;32m[.] html code coverage: ${COVERAGE_HTML_INDEX}  \033[0m"
fi
