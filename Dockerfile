# JDK8 is best supported by different JavaCard versions
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

# build and test the application
RUN gradle build

# build multiple JavaCard applications for different versions
RUN    gradle -Pjc_version=3.0.5 --console=verbose clean cap --info && mkdir --parents /tmp/javacard_build/3_0_5 && mv /tmp/build/*.cap /tmp/javacard_build/3_0_5/ \
    && gradle -Pjc_version=3.0.4 --console=verbose clean cap --info && mkdir --parents /tmp/javacard_build/3_0_4 && mv /tmp/build/*.cap /tmp/javacard_build/3_0_4/ \
    && gradle -Pjc_version=3.0.1 --console=verbose clean cap --info && mkdir --parents /tmp/javacard_build/3_0_1 && mv /tmp/build/*.cap /tmp/javacard_build/3_0_1/ \
    && gradle -Pjc_version=2.2.2 --console=verbose clean cap --info && mkdir --parents /tmp/javacard_build/2_2_2 && mv /tmp/build/*.cap /tmp/javacard_build/2_2_2/ \
    && gradle -Pjc_version=2.2.1 --console=verbose clean cap --info && mkdir --parents /tmp/javacard_build/2_2_1 && mv /tmp/build/*.cap /tmp/javacard_build/2_2_1/ \
    && tar cvzf javacard_build.tar.gz javacard_build

CMD exit