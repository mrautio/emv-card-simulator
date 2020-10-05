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
RUN gradle -Pjc_version=305u3 --console=verbose clean cap --info && tar cvzf /tmp/javacard_305_build.tar.gz --directory=/tmp/build pse.cap paymentapp.cap
RUN gradle -Pjc_version=304   --console=verbose clean cap --info && tar cvzf /tmp/javacard_304_build.tar.gz --directory=/tmp/build pse.cap paymentapp.cap
RUN gradle -Pjc_version=222   --console=verbose clean cap --info && tar cvzf /tmp/javacard_222_build.tar.gz --directory=/tmp/build pse.cap paymentapp.cap

CMD exit