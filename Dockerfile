FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3-pip \
    git \
    build-essential \
    openjdk-8-jdk \
    zlib1g-dev \
    zip \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install buildozer

WORKDIR /app
