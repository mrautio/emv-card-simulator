![Build and test](https://github.com/mrautio/emv-card-simulator/workflows/Docker%20Image%20CI/badge.svg)

# emv-card-simulator

JavaCard implementation of an EMV card for payment terminal testing.

## Building

### Cloning project

```sh
git clone --recurse-submodules https://github.com/mrautio/emv-card-simulator.git
```

### Docker build

If you don't want to install Java/Gradle, you may use Docker:

```sh
docker build -t emvcard-builder -f Dockerfile . && docker run -t emvcard-builder
```

### Gradle build

If you have all developer tools existing, then you can just use Gradle:

```sh
gradle build
```

## Update dependencies

```sh
gradle dependencies --write-locks
```

## Deploying to a SmartCard

If you have a SmartCard reader and a Global Platform compliant SmartCard, then you can deploy the application to an actual SmartCard:

```sh
gradle smartCardDeploy
```
