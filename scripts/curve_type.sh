#!/bin/bash

# Script to set curve type

# Prompt user for curve type
echo -e "Enter curve type BLS12, BN256, BN384 and BN512. Default is BN256."
read curve

# Set curve type
if [ -z "$curve" ]
then
    echo "Empty curve type invalid."
else
    if [ "$curve" == "BN256" ]
    then
        echo "" > lib/include/curve_type.hpp
    else
        echo "#define $curve" > lib/include/curve_type.hpp
    fi

    # Prompt user for build directory
    echo -e "Enter build directory"
    read directory

    # Re-compile and build
    cd $directory
    cmake ..
    make -j4
fi


