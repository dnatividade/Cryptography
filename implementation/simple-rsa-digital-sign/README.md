### First of all, you need to install Crypto++ library (8.2.0):
```
- Download the last version in: https://www.cryptopp.com/#download
- Unzip and compile:
make
make install
make test
```

### How to compile this example:
```
g++ main.cpp -o main -I/usr/local/include/cryptopp -L/usr/local/lib -lcryptopp
```
Done!
