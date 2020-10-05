package emvcardsimulator;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class PaymentApplication extends EmvApplet {

    public static void install(byte[] buffer, short offset, byte length) {
        (new PaymentApplication(buffer, offset, length)).register();
    }

    private Cipher rsaCipher;
    private MessageDigest shaMessageDigest;
    private byte[] challenge;
    private byte[] tag9f4cDynamicNumber;

    private RSAPrivateKey rsaPrivateKey = null;
    private short rsaPrivateKeyByteSize = 0;
    private byte[] pinCode = null;
    private boolean useRandom = true;

    private void processSetSettings(APDU apdu, byte[] buf) {
        short settingsId = Util.getShort(buf, ISO7816.OFFSET_P1);
        switch (settingsId) {
            // PIN CODE
            case 0x0001:
                Util.arrayCopy(buf, (short) ISO7816.OFFSET_CDATA, pinCode, (short) 0, (short) (buf[ISO7816.OFFSET_LC] & 0x00FF));
                break;
            // RESPONSE TEMPLATE
            case 0x0002:
                responseTemplateTag = Util.getShort(buf, ISO7816.OFFSET_CDATA);
                break;
            // FLAGS
            case 0x0003:
                short flags = Util.getShort(buf, ISO7816.OFFSET_CDATA);
                useRandom = ((flags & (1 << 0)) != 0);
                break;
            // ICC RSA KEY MODULUS
            case 0x0004:
                rsaPrivateKeyByteSize = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
                short keyLength = (short) (rsaPrivateKeyByteSize * 8);
                switch (keyLength) {
                    case (short) 1024:
                        keyLength = KeyBuilder.LENGTH_RSA_1024;
                        break;
                    case (short) 1280:
                        keyLength = KeyBuilder.LENGTH_RSA_1280;
                        break;
                    case (short) 1536:
                        keyLength = KeyBuilder.LENGTH_RSA_1536;
                        break;
                    case (short) 1984:
                        keyLength = KeyBuilder.LENGTH_RSA_1984;
                        break;
                    default:
                        throw new CryptoException(CryptoException.ILLEGAL_USE);
                }

                // XXX. JCardSim doesn't do "throw new CryptoException(CryptoException.ILLEGAL_VALUE)" as specified in the Java Card documentation. I.e. Sim allows any key size but JavaCard needs specific, hence keyLength is determined.
                rsaPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keyLength, false);
                rsaPrivateKey.clearKey();

                rsaPrivateKey.setModulus(buf, (short) ISO7816.OFFSET_CDATA, rsaPrivateKeyByteSize);
                break;
            // ICC RSA KEY PRIVATE EXPONENT
            case 0x0005:
                rsaPrivateKey.setExponent(buf, (short) ISO7816.OFFSET_CDATA, (short) (buf[ISO7816.OFFSET_LC] & 0x00FF));
                break;
            // FALLBACK READ RECORD
            case 0x0006:
                short dataLength = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
                defaultReadRecord = null;
                defaultReadRecord = new byte[dataLength];
                Util.arrayCopy(buf, (short) ISO7816.OFFSET_CDATA, defaultReadRecord, (short) 0, dataLength);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected PaymentApplication(byte[] buffer, short offset, byte length) {
        super();

        pinCode = new byte[] { (byte) 0x00, (byte) 0x00 };

        challenge = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);

        tag9f4cDynamicNumber = JCSystem.makeTransientByteArray((short) 3, JCSystem.CLEAR_ON_DESELECT);

        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        shaMessageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
    }

    private void processSelect(APDU apdu, byte[] buf) {
        // Check if PAN (tag A5) exists in the ICC
        if (EmvTag.findTag((short) 0x5A) != null) {
            arrayRandomFill(challenge);

            if (tagA5Fci != null) {
                short length = tagA5Fci.expandTlvToArray(tmpBuffer, (short) 0);
                EmvTag.setTag((short) 0xA5, tmpBuffer, (short) 0, (byte) length);
            }

            if (tag6fFci != null) {
                short length = tag6fFci.expandTlvToArray(tmpBuffer, (short) 0);
                EmvTag.setTag((short) 0x6F, tmpBuffer, (short) 0, (byte) length);
                sendResponse(apdu, buf, (short) 0x6F);
            } else {
                EmvApplet.logAndThrow(ISO7816.SW_APPLET_SELECT_FAILED);
            }

        } else {
            // NO PAN, we're probably in the setup phase
            EmvApplet.logAndThrow(ISO7816.SW_NO_ERROR);
        }
    }

    private void incrementApplicationTransactionCounter() {
        short applicationTransactionCounterTagId = (short) 0x9F36;
        EmvTag atcTag = EmvTag.findTag(applicationTransactionCounterTagId);
        if (atcTag != null) {
            short applicationTransactionCounter = Util.getShort(atcTag.getData(), (short) 0);
            applicationTransactionCounter += (short) 1;

            Util.setShort(tmpBuffer, (short) 0, applicationTransactionCounter);
            atcTag.setData(tmpBuffer, (short) 0, (byte) 2);
        }
    }

    private void processGenerateAc(APDU apdu, byte[] buf) {
        byte referenceControlParameter = buf[ISO7816.OFFSET_P1];
        byte requestCryptogramType = (byte) ((short) (referenceControlParameter >> ((byte) 6)) << ((byte) 6));

        byte responseCryptogramType = (byte) 0x40;
        switch (requestCryptogramType) {
            case (byte) 0x40: // TC
                responseCryptogramType = requestCryptogramType;
                break;
            case (byte) 0x80: // ARQC
                responseCryptogramType = requestCryptogramType;
                break;
            case (byte) 0x00: // AAC
                responseCryptogramType = (byte) 0x00;
                break;
            default:
                EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
                break;
        }

        tmpBuffer[0] = responseCryptogramType;
        EmvTag.setTag((short) 0x9F27, tmpBuffer, (short) 0, (byte) 1);

        incrementApplicationTransactionCounter();

        sendResponseTemplate(apdu, buf, responseTemplateGenerateAc);
    }

    private void externalAuthenticate(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x00) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        byte length = buf[ISO7816.OFFSET_LC];
        if (length < (byte) 8 || length > (byte) 16) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        // 6300 = Issuer authentication failed

        EmvApplet.logAndThrow(ISO7816.SW_NO_ERROR);
    }

    private void processGetData(APDU apdu, byte[] buf) {
        if (buf[ISO7816.OFFSET_LC] != (byte) 0x05) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        sendResponse(apdu, buf, Util.getShort(buf, ISO7816.OFFSET_P1));
    }

    private void processGetProcessingOptions(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x00) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buf[ISO7816.OFFSET_LC] != (byte) 0x02) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }
        if (buf[ISO7816.OFFSET_CDATA] != (byte) 0x83) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }
        if (buf[ISO7816.OFFSET_CDATA + 1] != (byte) 0x00) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        sendResponseTemplate(apdu, buf, responseTemplateGetProcessingOptions);
    }

    private void processDynamicDataAuthentication(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x0000) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        short signedDataSize = rsaPrivateKeyByteSize;

        // Build data to-be-encrypted

        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, signedDataSize, (byte) 0xBB);

        tmpBuffer[0] = (byte) 0x6A;
        tmpBuffer[1] = (byte) 0x05;
        tmpBuffer[2] = (byte) 0x01; // SHA-1 hash algo
        tmpBuffer[(short) (signedDataSize - 1)] = (byte) 0xBC;

        tmpBuffer[3] = (byte) tag9f4cDynamicNumber.length;
        arrayRandomFill(tag9f4cDynamicNumber);

        Util.arrayCopy(tag9f4cDynamicNumber, (short) 0, tmpBuffer, (short) 4, (short) tmpBuffer[3]);

        short checksumStartIndex = (short) (signedDataSize - 21);
        shaMessageDigest.reset();
        shaMessageDigest.update(tmpBuffer, (short) 1, (short) (checksumStartIndex - 1));        
        shaMessageDigest.doFinal(buf, (short) ISO7816.OFFSET_CDATA, (short) (buf[ISO7816.OFFSET_LC] & 0x00FF), tmpBuffer, checksumStartIndex);

        // Build Template

        rsaCipher.init(rsaPrivateKey, Cipher.MODE_ENCRYPT);
        rsaCipher.doFinal(tmpBuffer, (short) 0, signedDataSize, buf, (short) 0);

        EmvTag.setTag((short) 0x9F4B, buf, (short) 0, (byte) signedDataSize);

        sendResponseTemplate(apdu, buf, responseTemplateDda);
    }
    
    void comparePin(byte[] pinData, short offset) {
        // Cheapo pin compare for four(4) number pin

        if (pinCode.length != 2) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        short actualPin = Util.getShort(pinCode, (short) 0);
        short givenPin = Util.getShort(pinData, offset);
        short givenPinEnd = Util.getShort(pinData, (short) (offset + pinCode.length));

        final short swVerifyFail = (short) 0x63C3; // C3 = 3 tries left

        if (givenPinEnd != (short) 0xFFFF) {
            EmvApplet.logAndThrow(swVerifyFail);
        }

        if (actualPin != givenPin) {
            EmvApplet.logAndThrow(swVerifyFail);
        }
    }

    private void processVerifyPin(APDU apdu, byte[] buf) {
        short p1p2 = Util.getShort(buf, ISO7816.OFFSET_P1);
        if (p1p2 == (short) 0x0080) {
            if (buf[ISO7816.OFFSET_LC] != (byte) 0x08) {
                EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
            }

            comparePin(buf, (short) (ISO7816.OFFSET_CDATA + 1));
        } else if (p1p2 == (short) 0x0088) {
            short length = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
            if ((byte) length != (byte) 0x80) {
                EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
            }

            rsaCipher.init(rsaPrivateKey, Cipher.MODE_DECRYPT);
            rsaCipher.doFinal(buf, ISO7816.OFFSET_CDATA, length, tmpBuffer, (short) 0);

            if (tmpBuffer[0] != (byte) 0x7F) {
                EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
            }

            if (Util.arrayCompare(challenge, (short) 0, tmpBuffer, (short) 9, (short) challenge.length) != (byte) 0x00) {
                EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
            }

            comparePin(tmpBuffer, (short) 2);
        } else {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        EmvApplet.logAndThrow(ISO7816.SW_NO_ERROR);
    }

    private void arrayRandomFill(byte[] dst) {
        randomData.generateData(dst, (short) 0, (short) dst.length);
        if (!useRandom) {
            Util.arrayFillNonAtomic(dst, (short) 0, (short) dst.length, (byte) 0xAB);
        }
    }

    private void processGetChallenge(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x00) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        short outputLength = (short) challenge.length;

        if (buf[ISO7816.OFFSET_LC] != (byte) 0x00 && buf[ISO7816.OFFSET_LC] != (byte) outputLength) {
            EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
        }

        arrayRandomFill(challenge);

        sendResponse(apdu, buf, challenge, (short) 0, outputLength);
    }

    /**
     * Process PSE application selection and read records.
     */
    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer(); 

        ApduLog.addLogEntry(buf, (short) 0, (byte) (buf[ISO7816.OFFSET_LC] + 5));

        short cmd = Util.getShort(buf, ISO7816.OFFSET_CLA);

        switch (cmd) {
            case CMD_SELECT:
                processSelect(apdu, buf);
                return;
            case CMD_SET_SETTINGS:
                processSetSettings(apdu, buf);
                return;
            case CMD_SET_EMV_TAG:
                processSetEmvTag(apdu, buf);
                return;
            case CMD_SET_EMV_TAG_FUZZ:
                processSetEmvTagFuzz(apdu, buf);
                return;
            case CMD_SET_TAG_TEMPLATE:
                processSetTagTemplate(apdu, buf);
                return;
            case CMD_SET_READ_RECORD_TEMPLATE:
                processSetReadRecordTemplate(apdu, buf);
                return;
            case CMD_FACTORY_RESET:
                factoryReset(apdu, buf);
                return;
            case CMD_FUZZ_RESET:
                fuzzReset(apdu, buf);
                return;
            case CMD_LOG_CONSUME:
                consumeLogs(apdu, buf);
                return;
            default:
                break;
        }

        if (selectingApplet()) {
            return;
        }

        switch (cmd) {
            case CMD_READ_RECORD:
                processReadRecord(apdu, buf);
                break;
            case CMD_DDA:
                processDynamicDataAuthentication(apdu, buf);
                break;
            case CMD_VERIFY_PIN:
                processVerifyPin(apdu, buf);
                break;
            case CMD_GET_CHALLENGE:
                processGetChallenge(apdu, buf);
                break;
            case CMD_GET_DATA:
                processGetData(apdu, buf);
                break;
            case CMD_GET_PROCESSING_OPTIONS:
                processGetProcessingOptions(apdu, buf);
                break;
            case CMD_GENERATE_AC:
                processGenerateAc(apdu, buf);
                break;
            case CMD_EXTERNAL_AUTHENTICATE:
                externalAuthenticate(apdu, buf);
                break;
            default:
                EmvApplet.logAndThrow(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    }
}
