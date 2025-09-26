FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    zip \
    openjdk-11-jdk \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install buildozer

WORKDIR /app
COPY . .

CMD ["buildozer", "android", "debug"]
