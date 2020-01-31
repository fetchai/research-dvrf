#!/bin/bash

# Prompt user for file to save benchmarks to
echo -e "Enter file name for benchmarks"
read file

# Make build directory
if [ -d "build" ]; then rm -Rf build; fi
mkdir build

# Set mcl to BN256
{ echo "BN256";
  echo "build";
} | bash scripts/curve_type.sh

# Run benchmarks for all curves with mcl BN256
./build/lib/benchmarks/consensusBenchmarks >> "$file"

echo "BLS12" >> "$file"

# Change curve type to BLS12
{ echo "BLS12";
  echo "build";
} | bash scripts/curve_type.sh

# Run benchmarks for mcl implementations
./build/lib/benchmarks/consensusBenchmarks "dfinity_dvrf_functions - CryptoMcl" >> "$file"
./build/lib/benchmarks/consensusBenchmarks "glow_dvrf_functions - CryptoMcl" >> "$file"

echo "BN384" >> "$file"

# Change curve type to BN384
{ echo "BN384";
  echo "build";
} | bash scripts/curve_type.sh

# Run benchmarks for mcl implementations
./build/lib/benchmarks/consensusBenchmarks "dfinity_dvrf_functions - CryptoMcl" >> "$file"
./build/lib/benchmarks/consensusBenchmarks "glow_dvrf_functions - CryptoMcl" >> "$file"
