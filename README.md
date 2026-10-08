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

## Private test cards

Card setup APDU files in a git ignored `private/cards` directory are tested against [emvpt](https://github.com/mrautio/emvpt) with contact and contactless transactions, emvpt settings are in `private/config/settings.yaml`.

```sh
gradle testPrivateCards
```

## Library

`lib` packages the simulator applets with a host API (`emvcardsimulator.api`) for embedding the simulator to other
applications.

```sh
gradle -p lib build
```

```java
EmvCard card = new EmvCard(EmvCard.PROTOCOL_CONTACTLESS);
card.personalize(ApduScript.bundled("card_setup_ppse_apdus.yaml"));
card.personalize(ApduScript.bundled("card_setup_app_apdus.yaml"));
byte[] response = card.transmit(commandApdu);
```

A script may describe the card in a `card_information` entry, it is not sent to the card and the other tools skip it:

```yaml
- card_information:
    title: 'Test card'
- req: '00 A4 04 00 07 AF FF FF FF FF 12 34'
  res: '90 00'
```

Applets are installed when a script selects them. The APDU scripts of `src/main/rust/config` are bundled, and the ones of
`src/test/java/config` with a `test/` prefix, e.g. `test/card_setup_app_visa_contactless_apdus.yaml`.

## Fault injection

Each applet has a table of eight faults for terminal fuzzing and fault testing, see `src/main/rust/config/setup_fuzzing_apdus.yaml`.

```
SET FAULT    80 11 <entry 00-07> 00 Lc <kind> <INS> <interface> <trigger mode> <n> <kind specific data>   (Lc 00 clears the entry)
RESET        80 07 00 00 00              clear the faults and the fallback READ RECORD of the applet
SEED         80 07 00 01 02 <seed>       card wide seed of the fault random numbers, 0000 uses the card's random generator
```

A fault applies to a command when its trigger fires. Triggers are evaluated once per command, setup commands and
GET RESPONSE are not counted, GET RESPONSE keeps the faults of the command whose response it returns.

| Field | Values |
| --- | --- |
| INS | INS of the matching commands, `00` any command |
| Interface | `00` both, `01` contact, `02` contactless |
| Trigger mode | `00` always, `01` randomly 1 in n, `02` once on the nth matching command, `03` every nth matching command |

| Kind | Kind specific data |
| --- | --- |
| `01` tag value | tag (1-3 bytes) \|\| offset \|\| length \|\| strategy \|\| argument. Strategies: `00` random, `01` XOR argument (`00` flips one random bit), `02` fill with argument, `03` boundary values `00 01 7F 80 FE FF` in turn, `04` increment by the number of firings. The value is extended to offset + length bytes (at most 255) and the tag length is encoded for the mutated value. |
| `02` tag encoding | tag (1-3 bytes) \|\| mode \|\| argument 1 \|\| argument 2. Modes: `01` length + signed argument 1, `02` long form length of argument 1 (1-4) bytes, `03` indefinite length `80` (argument 1 not `00` appends `00 00`), `04` only the first tag byte announcing a subsequent byte, `05` constructed bit set, `06` argument 1 padding bytes of argument 2 before the tag, `07` omitted, `08` duplicated |
| `03` status word | SW1 SW2 \|\| `00` command is not processed and has no response data, `01` command is processed and its response data is sent |
| `04` response chain | mode \|\| argument. Modes: `01` GET RESPONSE repeats the same part and `61xx` forever, `02` `61xx` announces argument bytes, `03` `6Cxx` gives argument as the exact length, `04` last argument bytes of the response are not sent, `05` response is sent in parts of argument bytes with `61xx`, also with T=1 and contactless |
| `05` delay | number of busy-wait units (2 bytes) before the command is processed, the duration of a unit depends on the card. A real card may send waiting time extensions while busy. |

Random values come from the seeded generator when a seed is set, its sequence restarts when the seed is set, when the
faults are cleared and at card reset. A tag's random value is the same in all of its serializations of a command, e.g. in the
response and the CDA hash. For example, the second GENERATE AC after the fault is set returns `6985` without processing:

```
80 11 00 00 08 03 AE 00 02 02 69 85 00
```

## Update dependencies

Run the [GitHub Actions Workflow](https://github.com/mrautio/emv-card-simulator/actions/workflows/update-dependencies.yml).

## Deploying to a SmartCard

If you have a SmartCard reader and a Global Platform compliant SmartCard, then you can deploy the application to an actual SmartCard. Common installation issue is to use incorrect JavaCard SDK version, set correct with jc_version.

```sh
# Deploy payment selection app to a JavaCard 2 SmartCard 
gradle deployPse -Pjc_version=2.2.2
# Deploy contactless payment selection app (PPSE) to a JavaCard 2 SmartCard
gradle deployPpse -Pjc_version=2.2.2
# Deploy the payment app to a JavaCard 2 SmartCard 
gradle deployPaymentApp -Pjc_version=2.2.2
```
