FROM gradle:jdk8

WORKDIR /tmp

COPY oracle_javacard_sdks ./oracle_javacard_sdks
COPY gradle.properties ./
COPY build.gradle ./
COPY config ./config
COPY gradle ./gradle
COPY src ./src

RUN gradle --no-daemon --console=verbose build cap

CMD exit