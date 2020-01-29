### Table of Contents :books:
* [Implementation Details](#implementation-details)
* [Running DKG with Server](#running-dkg-with-server)
* [Benchmarks DKG](#benchmarks-dkg)
* [Changing Curve Type ](#changing-curve-type)
* [Contributing](#contributing)

### Implementation Details :page_facing_up: <a name="implementation-details"></a>

We provide implementations of the pairing-based GLOW-DVRF and Dfinity-DVRF protocols with curves BN256, BN384, and BLS12-381, and DDH-DVRF with curve Ristretto255. The pairing-based protocols are implemented using [mcl](https://github.com/herumi/mcl) and [RELIC](https://github.com/relic-toolkit/relic), and the DDH-DVRF protocol with [Libsodium](https://github.com/jedisct1/libsodium). 

The DVRFs implemented in this library consist of two phases:

Phase 1. __Distributed Key Generation__ (DKG) as described in [[1]](#1), or, in the case GLOW-DVRF, as in the [report](dvrfs-report.pdf)

This setup phase establishes the private and public key of each node (**sk**<sub>i</sub>, **vk**<sub>i</sub>) and the global public key **pk**, as described in [Section 3](dvrfs-report.pdf). No single node, or collection of nodes with size less than the chosen threshold *t*, can gain any information on the global secret key implicitly associated with **pk**. 

Phase 2. __Decentralised Random Beacon__ (DRB)

Using the output of the setup phase random values can be generated in a series of rounds where the verifiable random value in round *r* is *SHA3-512(σ<sub>r</sub>)*, where *σ<sub>r</sub>* is a signature, under the global public key **pk** of the message *m = r||H(σ<sub>r−1</sub>)*, where *H(σ<sub>r−1</sub>)* is the hash of the signature produced in round *r−1*. 

The communication layer by which the nodes exchange messages is implemented for local and network nodes. The _local node_ requires all peers to be created _within the same process_ and is set up to simulate network latency by sampling message delivery times from a Gamma distribution. Network nodes can be run from different machines identifying each other by their IP address, however they have only been tested with local host. Each node is equipped with an ECDSA key pair which it uses to sign all outgoing messages allowing receivers to authenticate the sender.  To run the protocol, all nodes are connected point-to-point with other nodes and have access to a secure private channel with each connection, which we have implemented using [Noise-C](https://github.com/rweather/noise-c), and a [broadcast channel](https://en.wikipedia.org/wiki/Atomic_broadcast) for sending messages, for which we provide our own implementation of the Protocol for Reliable Broadcast in [[2]](#2).

### Running DKG with Server :computer: <a name="running-dkg-with-server"></a>
Using _network nodes_, the DKG can be executed _by different processes_ on the same computer. Each node is run in its own terminal, and the nodes find each other by registering their identity with a server, which acts to allow nodes to connect to one another. To begin, we start the server listening to incoming connections
```bash 
./apps/client_server/server/Server -y
```
The default port number for the server is 1025 which can be changed, along with the other options, using help
```bash
./apps/client_server/server/Server --help
```
To start a node, one argument specifying the node's unique port number is required
```bash
./apps/client_server/client/Client [port number] 
```
The remaining optional arguments have default values which can be viewed using `--help`.

Of importance is the total number of nodes, N, taking part in the DKG, which is set to 4 by default. In order for the DKG to start, N nodes, each with a unique port number, must be running.

Each client upon starting sends the server its registration information, which consists of its name, port number, ECDSA public key, and signed Diffie-Hellman public key. If a new connection is established the server terminal will display a log message of the form 
```bash 
[date time] [fetch::logger] [info] [server] AddConnection to ClientName
```
The server then sends the new client the registration information of all existing clients, and notifies the latter of the new client. Clients will then attempt to connect to one another using the registration information from the server, and, once connected to N - 1 peers, begin the DKG. Note, the server is only required in the initial setup to allow nodes to find each other, and, therefore, is set to terminate after a specified delay time. The lifespan of the server is an optional argument and can be changed by using help. 



### Benchmarks DKG :factory: <a name="benchmarks-dkg"></a>
DKG can be run on local or network nodes with custom inputs for the number of nodes and threshold. The app outputs the following benchmarks for different stages of the DKG, where average is over all nodes in network:
1. Average pre-DKG sync time: time for a node to establish connections to others and receive broadcasts from everyone else stating their readiness for beginning the DKG
2. Average DKG comunication time: time taken for a node to complete DKG communication, i.e. obtain all information to compute the group public key from completing the pre-DKG sync
3. Average group public key computation time : time for computing the group public key via Lagrange interpolation
4. Average random beacon time: time to compute the group signature for one round of the random beacon averages over all nodes
5. Total time: time from the first node beginning the pre-DKG sync and the last node to compute the group signature
6. Average DKG unit time: time for a node to complete group public key computation from starting the pre-dkg sync

Example with N = 15 local nodes with zero latency and threshold T = 8
```bash 
./apps/benchmark_dkg/BenchmarkDKG -N 15 -T 8
```

To view the app options and default parameters
```bash 
./apps/benchmark_dkg/BenchmarkDKG --help
```

### Changing Curve Type :information_source: <a name="changing-curve-type"></a>
The default curve when using MCL is BN256 but the apps can also be run with curves BN384 and BLS12-381. In order to change curve the app needs to be re-built and can be most easily done by running the below script from the root directory
```bash
bash scripts/curve_type.sh
```
The terminal will list the options and ask you to select which curve you would like. Enter the curve type and press enter, e.g.
```bash
Enter curve type BLS12, BN256 and BN384. Default is BN256.
>> BN384
```
The script will then ask for a build directory into which the library will be re-built with the curve type change e.g.
```bash
Enter build directory
>> build
```
Note, if an invalid curve type is entered then the default choice of BN256 will be used. After changing the curve type, this curve will continued to be used in the apps until a new curve is selected.

### Contributing <a name="contributing"></a>

We welcome any contributions to this repository. If you would like to contribute, please make changes on a fork of the repository and submit a [pull request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request) for review and merging.

### References :mortar_board:

<a id="1">[1]</a>
Gennaro, R., Jarecki, S., Krawczyk, H., and Rabin, T. (2007) Secure Distributed Key Generation for Discrete-Log Based Cryptosystems

<a id="2">[2]</a>
Cachin, C., Kursawe, K., Petzold, F., and Shoup, V. (2001) Secure and Efficient Asynchronous Broadcast Protocols

<a id="2">[3]</a>
Galindo, D., Liu, J., Ordean, M., and Wong, J. (2020) Fully Distributed Verifiable Random Functions and their Application to Decentralised Random Beacons.
