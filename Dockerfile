# Use Ubuntu as base image
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV CXX=g++

# Install dependencies
RUN apt-get update && apt-get install -y \
    g++ \
    cmake \
    git \
    pkg-config \
    libssl-dev \
    zlib1g-dev \
    libsqlite3-dev \
    sqlite3 \
    libhiredis-dev \
    wget \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install httplib (header-only library)
RUN mkdir -p /usr/local/include && \
    cd /tmp && \
    wget https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h && \
    mv httplib.h /usr/local/include/

# Install nlohmann/json (header-only library)
RUN cd /tmp && \
    wget https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp && \
    mkdir -p /usr/local/include/nlohmann && \
    mv json.hpp /usr/local/include/nlohmann/

# Install jwt-cpp (header-only JWT library)
RUN cd /tmp && \
    wget https://github.com/Thalhammer/jwt-cpp/archive/refs/tags/v0.7.0.tar.gz && \
    tar -xzf v0.7.0.tar.gz && \
    cp -r jwt-cpp-0.7.0/include/* /usr/local/include/

# Install spdlog (header-only logging library)
RUN cd /tmp && \
    wget https://github.com/gabime/spdlog/archive/refs/tags/v1.12.0.tar.gz && \
    tar -xzf v1.12.0.tar.gz && \
    cp -r spdlog-1.12.0/include/* /usr/local/include/

# Install redis-plus-plus (C++ Redis client)
RUN cd /tmp && \
    git clone https://github.com/sewenew/redis-plus-plus.git && \
    cd redis-plus-plus && \
    mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make && make install && \
    ldconfig

# Copy source code
COPY main.cpp .

# Compile the application
RUN g++ -std=c++17 -pthread -O2 \
    -I/usr/local/include \
    -o api_server main.cpp \
    -lsqlite3 -lssl -lcrypto -static-libgcc -static-libstdc++ \
    /usr/local/lib/libredis++.a -lhiredis

# Expose port
EXPOSE 8080

# Run the application
CMD ["./api_server"]