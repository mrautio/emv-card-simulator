FROM gradle:jdk8

WORKDIR /tmp

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN apt-get update && apt-get install -y build-essential pkg-config libssl-dev libpcsclite-dev
COPY oracle_javacard_sdks ./oracle_javacard_sdks
COPY gradle.properties ./
COPY build.gradle ./
COPY config ./config
COPY gradle ./gradle
COPY src ./src
RUN gradle --no-daemon --console=verbose assemble cap --info

CMD exit