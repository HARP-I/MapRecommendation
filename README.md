# Privacy-preserving Map Recommendation System

We use MPC (Secure Multi-Party Computation) and HE (Homomorphic Encryption) for location privacy-preserving map recommendation.

## Dependency

Build & Install [Microsoft SEAL](https://github.com/microsoft/SEAL)

```bash
git clone https://github.com/microsoft/SEAL
cd SEAL
cmake -S . -B build
cmake --build build
sudo cmake --install build
```

## Build & Install

```bash
cd MapRecommendation
mkdir build && cd build
cmake ..
make
```

You will find `serverplatform` and `client` in the build dir.

## Help Manual

This prototype system uses the C/S architecture.

### ServerPlatform

```bash
./serverplatform --help
usage: ./serverplatform [options] ...
options:
  -h, --host    listening ip of serverplatform (string [=127.0.0.1])
  -p, --port    listening port of serverplatform (unsigned short [=51111])
  -6, --ipv6    ipv6 (int [=0])
  -?, --help    print this message
```

### Client

```bash
./client --help
usage: ./client [options] ...
options:
  -l, --server_platform_host    ip of platform (string [=127.0.0.1])
  -t, --server_platform_port    port of platform (unsigned short [=51111])
  -v, --variety_selected        variety of merchants (unsigned long [=1])
  -x, --xa                      coordinate1 of client (unsigned long [=123456789])
  -y, --ya                      coordinate2 of client (unsigned long [=132456888])
  -b, --plain_modulus_bits      bit length of plain modulus (unsigned long [=56])
  -r, --radius                  radius/thershold (unsigned long [=128])
  -d, --poly_modulus_degree     set degree of polynomial(2^d) (unsigned long [=13])
  -6, --ipv6                    ipv6 (int [=0])
  -?, --help                    print this message
```

### For Testing

```bash
bash mapRecoSys.sh
```

For more details, please refer to the code.
