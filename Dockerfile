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

# Copy source code
COPY main.cpp .

# Compile the application
RUN g++ -std=c++17 -pthread -O2 \
    -I/usr/local/include \
    -o api_server main.cpp

# Expose port
EXPOSE 8080

# Run the application
CMD ["./api_server"]