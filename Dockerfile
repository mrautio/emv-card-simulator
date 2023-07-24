FROM alpine:latest

WORKDIR /tmp

RUN apk add --no-cache bash gcc make pkgconfig openssl-dev rust cargo gradle>6.0.0 openjdk8=8.372.07-r0

# JDK8 is best supported by different JavaCard versions (<=3.0.4)
ENV JAVA_HOME /usr/lib/jvm/java-1.8-openjdk/
ENV PATH $PATH:/usr/lib/jvm/java-1.8-openjdk/bin
ENV JAVA_VERSION 8u372
ENV JAVA_ALPINE_VERSION 8.372.07-r0

COPY oracle_javacard_sdks ./oracle_javacard_sdks
COPY build.gradle gradle.properties ./
COPY config ./config
COPY gradle ./gradle
COPY src ./src

# build and test the application
RUN gradle build \
# build multiple JavaCard applications for different versions
    && gradle -Pjc_version=3.0.5 --console=verbose clean cap --info && mkdir --parents /tmp/javacard_build/3_0_5 && mv /tmp/build/*.cap /tmp/javacard_build/3_0_5/ \
    && gradle -Pjc_version=3.0.4 --console=verbose clean cap --info && mkdir --parents /tmp/javacard_build/3_0_4 && mv /tmp/build/*.cap /tmp/javacard_build/3_0_4/ \
    && gradle -Pjc_version=3.0.1 --console=verbose clean cap --info && mkdir --parents /tmp/javacard_build/3_0_1 && mv /tmp/build/*.cap /tmp/javacard_build/3_0_1/ \
    && gradle -Pjc_version=2.2.2 --console=verbose clean cap --info && mkdir --parents /tmp/javacard_build/2_2_2 && mv /tmp/build/*.cap /tmp/javacard_build/2_2_2/ \
    && gradle -Pjc_version=2.2.1 --console=verbose clean cap --info && mkdir --parents /tmp/javacard_build/2_2_1 && mv /tmp/build/*.cap /tmp/javacard_build/2_2_1/ \
    && tar cvzf javacard_build.tar.gz javacard_build

CMD exit