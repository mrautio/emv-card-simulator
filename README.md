![Build and test](https://github.com/mrautio/emv-card-simulator/workflows/Build%20and%20Test/badge.svg)

# emv-card-simulator

JavaCard implementation of an EMV card for payment terminal functional and security testing / fuzzing.

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

If you have all developer tools existing, or enter to `nix-shell`, then you can just use Gradle:

```sh
gradle build
```

## Update dependencies

Run the [GitHub Actions Workflow](https://github.com/mrautio/emv-card-simulator/actions/workflows/update-dependencies.yml).

## Deploying to a SmartCard

If you have a SmartCard reader and a Global Platform compliant SmartCard, then you can deploy the application to an actual SmartCard. Common installation issue is to use incorrect JavaCard SDK version, set correct with jc_version.

```sh
# Deploy payment selection app to a JavaCard 2 SmartCard 
gradle deployPse -Pjc_version=2.2.2
# Deploy the payment app to a JavaCard 2 SmartCard 
gradle deployPaymentApp -Pjc_version=2.2.2
```
