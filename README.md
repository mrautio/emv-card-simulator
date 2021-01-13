![Build and test](https://github.com/mrautio/emv-card-simulator/workflows/Build%20and%20Test/badge.svg)

# emv-card-simulator

JavaCard implementation of an EMV card for payment terminal functional and security testing.

If you need a payment terminal simulator for testing, try [emvpt](https://github.com/mrautio/emvpt) project.

## Building

### Cloning project

```sh
git clone --recurse-submodules https://github.com/mrautio/emv-card-simulator.git
```

### Docker build

If you don't want to install Java8/Gradle(>6), you may use Docker:

```sh
docker build -t emvcard-builder -f Dockerfile .
```

### Gradle build

If you have all developer tools existing, then you can just use Gradle:

```sh
gradle build
```

## Update dependencies

```sh
# NOTE: checkstyle version is fixed in build.gradle
gradle dependencies --write-locks
gradle --write-verification-metadata sha512 help
src/test/rust/simulator> cargo upgrade && cargo update && cargo audit
src/main/rust/cardtool> cargo upgrade && cargo update && cargo audit
```

## Deploying to a SmartCard

If you have a SmartCard reader and a Global Platform compliant SmartCard, then you can deploy the application to an actual SmartCard:

```sh
gradle smartCardDeploy
```
