package emvcardsimulator;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
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
                rsaPrivateKey.setModulus(buf, (short) ISO7816.OFFSET_CDATA, (short) (buf[ISO7816.OFFSET_LC] & 0x00FF));
                rsaPrivateKeyByteSize = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
                break;
            // ICC RSA KEY PRIVATE EXPONENT
            case 0x0005:
                rsaPrivateKey.setExponent(buf, (short) ISO7816.OFFSET_CDATA, (short) (buf[ISO7816.OFFSET_LC] & 0x00FF));
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

        rsaPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
        rsaPrivateKey.clearKey();

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
                ISOException.throwIt(ISO7816.SW_APPLET_SELECT_FAILED);
            }

        } else {
            // NO PAN, we're probably in the setup phase
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }
    }

    private void incrementApplicationTransactionCounter() {
        short applicationTransactionCounterTagId = (short) 0x9F36;
        EmvTag atcTag = EmvTag.findTag(applicationTransactionCounterTagId);
        if (atcTag != null) {
            short applicationTransactionCounter = Util.getShort(atcTag.getData(), (short) 0);
            applicationTransactionCounter += 1;

            Util.setShort(tmpBuffer, (short) 0, applicationTransactionCounter);
            atcTag.setData(tmpBuffer, (short) 0, (byte) 2);
        }
    }

    private void processGenerateAc(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x4000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if (buf[ISO7816.OFFSET_LC] != (byte) 0x1D) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // TODO: check the query
        // (byte) 0x80, (byte) 0xAE, (byte) 0x40, (byte) 0x00, (byte) 0x1D, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x46, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x09, (byte) 0x78, (byte) 0x20, (byte) 0x07, (byte) 0x24, (byte) 0x21, (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x00

        incrementApplicationTransactionCounter();

        sendResponseTemplate(apdu, buf, responseTemplateGenerateAc);
    }

    private void processGetData(APDU apdu, byte[] buf) {
        if (buf[ISO7816.OFFSET_LC] != (byte) 0x05) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        sendResponse(apdu, buf, Util.getShort(buf, ISO7816.OFFSET_P1));
    }

    private void processGetProcessingOptions(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buf[ISO7816.OFFSET_LC] != (byte) 0x02) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (buf[ISO7816.OFFSET_CDATA] != (byte) 0x83) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (buf[ISO7816.OFFSET_CDATA + 1] != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        sendResponseTemplate(apdu, buf, responseTemplateGetProcessingOptions);
    }

    private void processDynamicDataAuthentication(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
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
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short actualPin = Util.getShort(pinCode, (short) 0);
        short givenPin = Util.getShort(pinData, offset);
        short givenPinEnd = Util.getShort(pinData, (short) (offset + pinCode.length));

        final short swVerifyFail = (short) 0x63C3; // C3 = 3 tries left

        if (givenPinEnd != (short) 0xFFFF) {
            ISOException.throwIt(swVerifyFail);
        }

        if (actualPin != givenPin) {
            ISOException.throwIt(swVerifyFail);
        }
    }

    private void processVerifyPin(APDU apdu, byte[] buf) {
        short p1p2 = Util.getShort(buf, ISO7816.OFFSET_P1);
        if (p1p2 == (short) 0x0080) {
            if (buf[ISO7816.OFFSET_LC] != (byte) 0x08) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            comparePin(buf, (short) (ISO7816.OFFSET_CDATA + 1));
        } else if (p1p2 == (short) 0x0088) {
            short length = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
            if ((byte) length != (byte) 0x80) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            rsaCipher.init(rsaPrivateKey, Cipher.MODE_DECRYPT);
            rsaCipher.doFinal(buf, ISO7816.OFFSET_CDATA, length, tmpBuffer, (short) 0);

            if (tmpBuffer[0] != (byte) 0x7F) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            if (Util.arrayCompare(challenge, (short) 0, tmpBuffer, (short) 9, (short) challenge.length) != (byte) 0x00) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);                
            }

            comparePin(tmpBuffer, (short) 2);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    private void arrayRandomFill(byte[] dst) {
        randomData.generateData(dst, (short) 0, (short) dst.length);
        if (!useRandom) {
            Util.arrayFillNonAtomic(dst, (short) 0, (short) dst.length, (byte) 0xAB);
        }
    }

    private void processGetChallenge(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short outputLength = (short) challenge.length;

        if (buf[ISO7816.OFFSET_LC] != (byte) 0x00 && buf[ISO7816.OFFSET_LC] != (byte) outputLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        arrayRandomFill(challenge);

        sendResponse(apdu, buf, challenge);
    }

    /**
     * Process PSE application selection and read records.
     */
    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer(); 

        short cmd = Util.getShort(buf, ISO7816.OFFSET_CLA);

        switch (cmd) {
            case CMD_SET_SETTINGS:
                processSetSettings(apdu, buf);
                break;            
            case CMD_SET_EMV_TAG:
                processSetEmvTag(apdu, buf);
                break;
            case CMD_SET_TAG_TEMPLATE:
                processSetTagTemplate(apdu, buf);
                break;
            case CMD_SET_READ_RECORD_TEMPLATE:
                processSetReadRecordTemplate(apdu, buf);
                break;
            case CMD_SELECT:
                processSelect(apdu, buf);
                break;
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
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    }
}
