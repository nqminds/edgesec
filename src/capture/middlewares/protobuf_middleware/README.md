The protobuf file need to be compiled separately.

Download and install the protobuf library 3.20.3
```bash
wget https://github.com/protocolbuffers/protobuf/releases/download/v3.20.3/protobuf-cpp-3.20.3.zip
unzip protobuf-cpp-3.20.3.zip
cd protobuf-cpp-3.20.3
./autogen.sh && ./configure && make && sudo make install
```
The installed `protoc` binary will be located in `/usr/local/bin`.

Download and compile the protobuf-c library
```bash
wget https://github.com/protobuf-c/protobuf-c/releases/download/v1.4.1/protobuf-c-1.4.1.tar.gz
tar -xvf protobuf-c-1.4.1.tar.gz
cd protobuf-c-1.4.1
./autogen.sh && ./configure && make
```

The compiled protobuf-c extension will be located at `protobuf-c/protoc-c/protoc-gen-c`.

To compile the protobuf definitions in `protos` folder and generate the output files in `protobuf_middleware` folder use:
```bash
protoc --plugin=protoc-gen-c=absolute_path_to_protoc-gen-c -I./protos --c_out=./ ./protos/test.proto
```
