package emvcardsimulator;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacardx.crypto.Cipher;

public class PaymentApplication extends EmvApplet {

    public static void install(byte[] buffer, short offset, byte length) {
        (new PaymentApplication(buffer, offset, length)).register();
    }

    private static final byte PIN_TRY_LIMIT = (byte) 3;

    // Cryptogram Information Data cryptogram types
    private static final byte CID_AAC = (byte) 0x00;
    private static final byte CID_TC = (byte) 0x40;
    private static final byte CID_ARQC = (byte) 0x80;

    // Transaction states, reset on applet selection
    private static final byte STATE_IDLE = (byte) 0x00;
    private static final byte STATE_GPO_DONE = (byte) 0x01;
    private static final byte STATE_ARQC_ISSUED = (byte) 0x02;
    private static final byte STATE_COMPLETED = (byte) 0x03;

    private static final short OFFSET_STATE = (short) 0;
    private static final short OFFSET_EXTERNAL_AUTHENTICATE_DONE = (short) 1;
    private static final short OFFSET_ISSUER_AUTHENTICATION_FAILED = (short) 2;

    // ARPC generation methods (EMV Book 2, 8.2 Issuer Authentication)
    private static final byte ARPC_METHOD_1 = (byte) 0x01;
    private static final byte ARPC_METHOD_2 = (byte) 0x02;

    private Cipher rsaCipher;
    private MessageDigest shaMessageDigest;
    private byte[] challenge;
    private boolean[] challengeValid;
    private byte[] tag9f4cDynamicNumber;
    private byte[] transactionState;

    // DOL related data of the current transaction, needed for CDA Transaction Data Hash Code
    private byte[] pdolData;
    private short pdolDataLength = 0;
    private byte[] cdol1Data;
    private short cdol1DataLength = 0;
    private byte[] cdol2Data;
    private short cdol2DataLength = 0;

    private TagTemplate responseTemplateGenerateAcCda;

    private RSAPrivateKey rsaPrivateKey = null;
    private short rsaPrivateKeyByteSize = 0;
    private byte[] pinBlock = null;
    private boolean useRandom = true;

    // ICC Application Cryptogram Master Key MK_AC, Application Cryptogram is static tag 9F26 when not set
    private DESKey applicationCryptogramMasterKey = null;
    // Include Issuer Application Data in Application Cryptogram generation (EMV Book 2, CCD 8.1.1)
    private boolean includeIssuerApplicationDataInAc = false;
    private Cipher desCipher;
    // Application Cryptogram Session Key SK_AC halves for ISO/IEC 9797-1 MAC Algorithm 3
    private DESKey sessionKeyLeft;
    private DESKey sessionKeyRight;
    private byte[] macBlock;
    private short macBlockOffset = 0;
    private byte arpcMethod = ARPC_METHOD_1;
    // Application Cryptogram of the first GENERATE AC, input for ARPC and secure messaging session key
    private byte[] firstApplicationCryptogram;

    // ICC Secure Messaging for Integrity Master Key MK_SMI (EMV Book 2, 9.2)
    private DESKey secureMessagingMacMasterKey = null;
    // MAC chaining value of issuer script commands (EMV Book 2, 9.2.3.1)
    private byte[] secureMessagingMacChain;
    // APPLICATION BLOCK state (EMV Book 3, 6.5.1)
    private boolean applicationBlocked = false;

    protected void processSetSettings(APDU apdu, byte[] buf, short dataLength) {
        short settingsId = Util.getShort(buf, ISO7816.OFFSET_P1);
        switch (settingsId) {
            // PIN CODE
            case 0x0001:
                setPin(buf, (short) ISO7816.OFFSET_CDATA, dataLength);
                break;
            // RESPONSE TEMPLATE
            case 0x0002:
                if (dataLength != (short) 2) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                responseTemplateTag = Util.getShort(buf, ISO7816.OFFSET_CDATA);
                break;
            // FLAGS
            case 0x0003:
                if (dataLength != (short) 2) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                short flags = Util.getShort(buf, ISO7816.OFFSET_CDATA);
                useRandom = ((flags & (1 << 0)) != 0);
                includeIssuerApplicationDataInAc = ((flags & (1 << 1)) != 0);
                break;
            // ICC RSA KEY MODULUS
            case 0x0004:
                rsaPrivateKeyByteSize = dataLength;
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
                if (rsaPrivateKey == null) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                rsaPrivateKey.setExponent(buf, (short) ISO7816.OFFSET_CDATA, dataLength);
                break;
            // FALLBACK READ RECORD
            case 0x0006:
                defaultReadRecord = null;
                defaultReadRecord = new byte[dataLength];
                Util.arrayCopy(buf, (short) ISO7816.OFFSET_CDATA, defaultReadRecord, (short) 0, dataLength);
                break;
            // ICC APPLICATION CRYPTOGRAM MASTER KEY (double length Triple DES), empty data clears the key
            case 0x0007:
                applicationCryptogramMasterKey = setMasterKey(applicationCryptogramMasterKey, buf, dataLength);
                break;
            // ARPC METHOD
            case 0x0008:
                if (dataLength != (short) 1) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                if (buf[ISO7816.OFFSET_CDATA] != ARPC_METHOD_1 && buf[ISO7816.OFFSET_CDATA] != ARPC_METHOD_2) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                arpcMethod = buf[ISO7816.OFFSET_CDATA];
                break;
            // ICC SECURE MESSAGING FOR INTEGRITY MASTER KEY (double length Triple DES), empty data clears the key
            case 0x0009:
                secureMessagingMacMasterKey = setMasterKey(secureMessagingMacMasterKey, buf, dataLength);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * Set double length Triple DES master key from command data, empty data clears the key.
     */
    private static DESKey setMasterKey(DESKey key, byte[] buf, short dataLength) {
        if (dataLength == (short) 0) {
            if (key != null) {
                key.clearKey();
            }
            return key;
        }
        if (dataLength != (short) 16) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (key == null) {
            key = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        }
        key.setKey(buf, (short) ISO7816.OFFSET_CDATA);
        return key;
    }

    private static boolean isKeySet(DESKey key) {
        return key != null && key.isInitialized();
    }

    protected void factoryReset() {
        super.factoryReset();

        applicationBlocked = false;
    }

    protected PaymentApplication(byte[] buffer, short offset, byte length) {
        super();

        // Default PIN 0000 as plaintext PIN block (EMV Book 3, 6.5.12)
        pinBlock = new byte[] { (byte) 0x24, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };

        challenge = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        challengeValid = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_DESELECT);

        tag9f4cDynamicNumber = JCSystem.makeTransientByteArray((short) 3, JCSystem.CLEAR_ON_DESELECT);

        transactionState = JCSystem.makeTransientByteArray((short) 3, JCSystem.CLEAR_ON_DESELECT);
        firstApplicationCryptogram = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        secureMessagingMacChain = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);

        pdolData = new byte[255];
        cdol1Data = new byte[255];
        cdol2Data = new byte[255];

        responseTemplateGenerateAcCda = new TagTemplate();

        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        shaMessageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);

        desCipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
        sessionKeyLeft = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_DES, false);
        sessionKeyRight = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_DES, false);
        macBlock = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Set PIN from packed BCD digits, optionally padded with F nibbles, e.g. 12 34 or 12 34 5F.
     */
    private void setPin(byte[] src, short offset, short length) {
        if (length < (short) 2 || length > (short) 6) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) 8, (byte) 0xFF);
        Util.arrayCopyNonAtomic(src, offset, tmpBuffer, (short) 1, length);

        byte digitCount = (byte) 0;
        boolean filler = false;
        for (short i = (short) 2; i < (short) 16; i++) {
            byte nibble = tmpBuffer[(short) (i / 2)];
            if (i % 2 == 0) {
                nibble = (byte) ((nibble >> 4) & 0x0F);
            } else {
                nibble = (byte) (nibble & 0x0F);
            }

            if (nibble == (byte) 0x0F) {
                filler = true;
            } else if (filler || nibble > (byte) 9) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            } else {
                digitCount++;
            }
        }

        if (digitCount < (byte) 4 || digitCount > (byte) 12) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        tmpBuffer[0] = (byte) (0x20 | digitCount);
        Util.arrayCopy(tmpBuffer, (short) 0, pinBlock, (short) 0, (short) 8);

        setPinTryCounter(PIN_TRY_LIMIT);
    }

    private byte getPinTryCounter() {
        EmvTag pinTryCounterTag = EmvTag.findTag((short) 0x9F17);
        if (pinTryCounterTag == null || pinTryCounterTag.getLength() == (byte) 0) {
            return PIN_TRY_LIMIT;
        }

        return pinTryCounterTag.getData()[0];
    }

    private void setPinTryCounter(byte pinTryCounter) {
        tmpBuffer[0] = pinTryCounter;
        EmvTag.setTag((short) 0x9F17, tmpBuffer, (short) 0, (byte) 1);
    }

    private void requireRsaPrivateKey() {
        if (rsaPrivateKey == null || !rsaPrivateKey.isInitialized()) {
            EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    protected void processSelect(APDU apdu, byte[] buf) {
        if (applicationBlocked) {
            EmvApplet.logAndThrow(SW_SELECTED_FILE_INVALIDATED);
        }

        // Check if PAN (tag A5) exists in the ICC
        if (EmvTag.findTag((short) 0x5A) != null) {
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

            // ATC must not wrap around, application is blocked when the maximum value is reached
            if (applicationTransactionCounter == (short) 0xFFFF) {
                EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            applicationTransactionCounter += (short) 1;

            Util.setShort(tmpBuffer, (short) 0, applicationTransactionCounter);
            atcTag.setData(tmpBuffer, (short) 0, (byte) 2);
        }
    }

    /**
     * Store DOL related data from command data and check its length against the DOL, if the DOL exists.
     */
    private short storeDataObjectListData(short dolTagId, byte[] buf, short dataLength, byte[] dst) {
        short expectedLength = findDataObjectListEntry(dolTagId, (short) 0);
        if (expectedLength >= 0 && expectedLength != dataLength) {
            EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopyNonAtomic(buf, (short) ISO7816.OFFSET_CDATA, dst, (short) 0, dataLength);

        return dataLength;
    }

    private void processGenerateAc(APDU apdu, byte[] buf, short dataLength) {
        if (buf[ISO7816.OFFSET_P2] != (byte) 0x00) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        byte referenceControlParameter = buf[ISO7816.OFFSET_P1];
        byte requestCryptogramType = (byte) (referenceControlParameter & (byte) 0xC0);
        final boolean cdaRequested = (referenceControlParameter & (byte) 0x10) != 0;

        boolean secondGenerateAc = false;
        switch (transactionState[OFFSET_STATE]) {
            case STATE_GPO_DONE:
                break;
            case STATE_ARQC_ISSUED:
                secondGenerateAc = true;
                break;
            default:
                EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                break;
        }

        switch (requestCryptogramType) {
            case CID_TC:
            case CID_AAC:
                break;
            case CID_ARQC:
                // Second GENERATE AC completes the transaction, only TC or AAC can be requested
                if (secondGenerateAc) {
                    EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
                }
                break;
            default:
                EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
                break;
        }

        if (secondGenerateAc) {
            cdol2DataLength = storeDataObjectListData((short) 0x008D, buf, dataLength, cdol2Data);
        } else {
            cdol1DataLength = storeDataObjectListData((short) 0x008C, buf, dataLength, cdol1Data);
        }

        if (secondGenerateAc && isApplicationCryptogramMasterKeySet()) {
            verifyIssuerAuthenticationDataInCdol2();
        }

        byte responseCryptogramType = requestCryptogramType;

        // Transaction is declined when issuer authentication has failed
        if (responseCryptogramType == CID_TC && transactionState[OFFSET_ISSUER_AUTHENTICATION_FAILED] != (byte) 0x00) {
            responseCryptogramType = CID_AAC;
        }

        // Blocked application returns only AAC
        if (applicationBlocked) {
            responseCryptogramType = CID_AAC;
        }

        tmpBuffer[0] = responseCryptogramType;
        EmvTag.setTag((short) 0x9F27, tmpBuffer, (short) 0, (byte) 1);

        if (isApplicationCryptogramMasterKeySet()) {
            if (secondGenerateAc) {
                generateApplicationCryptogram(cdol2Data, cdol2DataLength);
            } else {
                generateApplicationCryptogram(cdol1Data, cdol1DataLength);
            }
        }

        if (!secondGenerateAc) {
            EmvTag applicationCryptogram = EmvTag.findTag((short) 0x9F26);
            if (applicationCryptogram != null && applicationCryptogram.getLength() == (byte) 8) {
                Util.arrayCopyNonAtomic(applicationCryptogram.getData(), (short) 0, firstApplicationCryptogram, (short) 0, (short) 8);
                // First script command MAC is chained from the Application Cryptogram
                Util.arrayCopyNonAtomic(applicationCryptogram.getData(), (short) 0, secureMessagingMacChain, (short) 0, (short) 8);
            }
        }

        // CDA signature is not generated for AAC
        if (cdaRequested && responseCryptogramType != CID_AAC) {
            sendCombinedDataAuthenticationResponse(apdu, buf, secondGenerateAc);
        } else {
            sendResponseTemplate(apdu, buf, responseTemplateGenerateAc);
        }

        if (responseCryptogramType == CID_ARQC) {
            transactionState[OFFSET_STATE] = STATE_ARQC_ISSUED;
        } else {
            transactionState[OFFSET_STATE] = STATE_COMPLETED;
        }
    }

    private boolean isApplicationCryptogramMasterKeySet() {
        return isKeySet(applicationCryptogramMasterKey);
    }

    /**
     * Verify Issuer Authentication Data (tag 91) included in CDOL2 related data (EMV Book 3, CCD 6.5.5).
     * Zero filled data means that the terminal did not receive Issuer Authentication Data.
     */
    private void verifyIssuerAuthenticationDataInCdol2() {
        short offset = findDataObjectListEntry((short) 0x008D, (short) 0x0091);
        if (offset < 0) {
            return;
        }

        short length = dataObjectListEntryLength;
        boolean received = false;
        for (short i = (short) 0; i < length; i++) {
            if (cdol2Data[(short) (offset + i)] != (byte) 0x00) {
                received = true;
                break;
            }
        }

        if (received && !verifyIssuerAuthenticationData(cdol2Data, offset, length)) {
            transactionState[OFFSET_ISSUER_AUTHENTICATION_FAILED] = (byte) 0x01;
        }
    }

    /**
     * Verify ARPC in Issuer Authentication Data (tag 91) with the Application Cryptogram Session Key (EMV Book 2, 8.2).
     * Method 1: Issuer Authentication Data := ARPC (8) || ARC (2), ARPC := DES3(SK_AC)[ARQC XOR (ARC || '00' .. '00')]
     * Method 2: Issuer Authentication Data := ARPC (4) || CSU (4) || Proprietary Authentication Data (0-8),
     *           ARPC := MAC(SK_AC)[ARQC || CSU || Proprietary Authentication Data] with s = 4
     */
    private boolean verifyIssuerAuthenticationData(byte[] src, short offset, short length) {
        EmvTag applicationTransactionCounter = EmvTag.findTag((short) 0x9F36);
        if (applicationTransactionCounter == null || applicationTransactionCounter.getLength() != (byte) 2) {
            return false;
        }

        deriveApplicationCryptogramSessionKey(applicationTransactionCounter.getData());

        short arpcLength;
        if (arpcMethod == ARPC_METHOD_1) {
            if (length != (short) 10) {
                return false;
            }
            arpcLength = (short) 8;

            Util.arrayCopyNonAtomic(firstApplicationCryptogram, (short) 0, tmpBuffer, (short) 0, (short) 8);
            tmpBuffer[0] ^= src[(short) (offset + 8)];
            tmpBuffer[1] ^= src[(short) (offset + 9)];

            // Single block CBC-MAC with output transformation 3 equals Triple DES encryption
            macInit();
            macUpdate(tmpBuffer, (short) 0, (short) 8);
            macOutputTransformation(tmpBuffer, (short) 0);
        } else {
            if (length < (short) 8 || length > (short) 16) {
                return false;
            }
            arpcLength = (short) 4;

            macInit();
            macUpdate(firstApplicationCryptogram, (short) 0, (short) 8);
            macUpdate(src, (short) (offset + 4), (short) 4);
            // Proprietary Authentication Data is included only when indicated by CSU (EMV Book 2, CCD 8.2.2)
            if ((src[(short) (offset + 4)] & (byte) 0x80) != 0) {
                macUpdate(src, (short) (offset + 8), (short) (length - 8));
            }
            macFinal(tmpBuffer, (short) 0);
        }

        return Util.arrayCompare(tmpBuffer, (short) 0, src, offset, arpcLength) == (byte) 0x00;
    }

    /**
     * Generate Application Cryptogram (tag 9F26) with Triple DES (EMV Book 2, 8.1 Application Cryptogram Generation).
     * MAC is computed over the CDOL related data of the GENERATE AC command, AIP and ATC,
     * and optionally the Issuer Application Data as in the Common Core Definitions.
     */
    private void generateApplicationCryptogram(byte[] cdolData, short cdolDataLength) {
        EmvTag applicationTransactionCounter = EmvTag.findTag((short) 0x9F36);
        EmvTag applicationInterchangeProfile = EmvTag.findTag((short) 0x0082);
        if (applicationTransactionCounter == null || applicationTransactionCounter.getLength() != (byte) 2
            || applicationInterchangeProfile == null || applicationInterchangeProfile.getLength() != (byte) 2) {
            EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        deriveApplicationCryptogramSessionKey(applicationTransactionCounter.getData());

        macInit();
        macUpdate(cdolData, (short) 0, cdolDataLength);
        macUpdate(applicationInterchangeProfile.getData(), (short) 0, (short) 2);
        macUpdate(applicationTransactionCounter.getData(), (short) 0, (short) 2);
        if (includeIssuerApplicationDataInAc) {
            EmvTag issuerApplicationData = EmvTag.findTag((short) 0x9F10);
            if (issuerApplicationData != null) {
                macUpdate(issuerApplicationData.getData(), (short) 0, (short) (issuerApplicationData.getLength() & 0x00FF));
            }
        }
        macFinal(tmpBuffer, (short) 0);

        EmvTag.setTag((short) 0x9F26, tmpBuffer, (short) 0, (byte) 8);
    }

    /**
     * Derive Application Cryptogram Session Key SK_AC from MK_AC and ATC (EMV Book 2, A1.3.1 Common Session Key Derivation Option).
     * R := ATC || '00' || '00' || '00' || '00' || '00' || '00'
     */
    private void deriveApplicationCryptogramSessionKey(byte[] applicationTransactionCounter) {
        deriveSessionKey(applicationCryptogramMasterKey, applicationTransactionCounter, (short) 2);
    }

    /**
     * Derive session key from master key MK and diversification value R, R is zero padded to 8 bytes
     * (EMV Book 2, A1.3.1 Common Session Key Derivation Option).
     * SK := DES3(MK)[R0 || R1 || 'F0' || R3 .. R7] || DES3(MK)[R0 || R1 || '0F' || R3 .. R7]
     */
    private void deriveSessionKey(DESKey masterKey, byte[] diversification, short diversificationLength) {
        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) 16, (byte) 0x00);
        Util.arrayCopyNonAtomic(diversification, (short) 0, tmpBuffer, (short) 0, diversificationLength);
        Util.arrayCopyNonAtomic(diversification, (short) 0, tmpBuffer, (short) 8, diversificationLength);
        tmpBuffer[2] = (byte) 0xF0;
        tmpBuffer[10] = (byte) 0x0F;

        desCipher.init(masterKey, Cipher.MODE_ENCRYPT);
        desCipher.doFinal(tmpBuffer, (short) 0, (short) 16, tmpBuffer, (short) 0);

        sessionKeyLeft.setKey(tmpBuffer, (short) 0);
        sessionKeyRight.setKey(tmpBuffer, (short) 8);

        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) 16, (byte) 0x00);
    }

    /**
     * Start MAC computation with ISO/IEC 9797-1 MAC Algorithm 3 using DES (EMV Book 2, A1.2.1), initial value zero.
     */
    private void macInit() {
        Util.arrayFillNonAtomic(macBlock, (short) 0, (short) 8, (byte) 0x00);
        macBlockOffset = (short) 0;
        desCipher.init(sessionKeyLeft, Cipher.MODE_ENCRYPT);
    }

    /**
     * CBC mode with the leftmost session key block: H(i) := DES(K_SL)[X(i) XOR H(i-1)].
     */
    private void macUpdate(byte[] src, short offset, short length) {
        for (short i = (short) 0; i < length; i++) {
            macBlock[macBlockOffset] ^= src[(short) (offset + i)];
            macBlockOffset++;
            if (macBlockOffset == (short) 8) {
                desCipher.doFinal(macBlock, (short) 0, (short) 8, macBlock, (short) 0);
                macBlockOffset = (short) 0;
            }
        }
    }

    /**
     * Pad with ISO/IEC 9797-1 padding method 2 and compute the 8-byte MAC: H(B+1) := DES(K_SL)[DES^-1(K_SR)[H(B)]].
     */
    private void macFinal(byte[] dst, short dstOffset) {
        macBlock[macBlockOffset] ^= (byte) 0x80;
        desCipher.doFinal(macBlock, (short) 0, (short) 8, macBlock, (short) 0);

        macOutputTransformation(dst, dstOffset);
    }

    /**
     * ISO/IEC 9797-1 output transformation 3 of the last CBC block: DES(K_SL)[DES^-1(K_SR)[H(B)]].
     */
    private void macOutputTransformation(byte[] dst, short dstOffset) {
        desCipher.init(sessionKeyRight, Cipher.MODE_DECRYPT);
        desCipher.doFinal(macBlock, (short) 0, (short) 8, macBlock, (short) 0);

        desCipher.init(sessionKeyLeft, Cipher.MODE_ENCRYPT);
        desCipher.doFinal(macBlock, (short) 0, (short) 8, dst, dstOffset);

        Util.arrayFillNonAtomic(macBlock, (short) 0, (short) 8, (byte) 0x00);
    }

    /**
     * Send GENERATE AC response with Signed Dynamic Application Data (EMV Book 2, 6.6 Combined DDA/Application Cryptogram Generation).
     */
    private void sendCombinedDataAuthenticationResponse(APDU apdu, byte[] buf, boolean secondGenerateAc) {
        requireRsaPrivateKey();

        // Unpredictable Number from the CDOL related data of this GENERATE AC
        byte[] unpredictableNumberSource = cdol1Data;
        short unpredictableNumberOffset = findDataObjectListEntry((short) 0x008C, (short) 0x9F37);
        if (secondGenerateAc) {
            short cdol2UnpredictableNumberOffset = findDataObjectListEntry((short) 0x008D, (short) 0x9F37);
            if (cdol2UnpredictableNumberOffset >= 0) {
                unpredictableNumberSource = cdol2Data;
                unpredictableNumberOffset = cdol2UnpredictableNumberOffset;
            }
        }
        if (unpredictableNumberOffset < 0) {
            EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        EmvTag applicationCryptogram = EmvTag.findTag((short) 0x9F26);
        if (applicationCryptogram == null || applicationCryptogram.getLength() != (byte) 8) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        // Format 2 response where Application Cryptogram is replaced by Signed Dynamic Application Data
        responseTemplateGenerateAcCda.setDataReplacingTag(responseTemplateGenerateAc, (short) 0x9F26, (short) 0x9F4B);

        short signedDataSize = rsaPrivateKeyByteSize;
        final short dynamicNumberLength = (short) tag9f4cDynamicNumber.length;

        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, signedDataSize, (byte) 0xBB);

        tmpBuffer[0] = (byte) 0x6A;
        tmpBuffer[1] = (byte) 0x05;
        tmpBuffer[2] = (byte) 0x01; // SHA-1 hash algo
        tmpBuffer[3] = (byte) (1 + dynamicNumberLength + 1 + 8 + 20);
        tmpBuffer[(short) (signedDataSize - 1)] = (byte) 0xBC;

        // ICC Dynamic Data: ICC Dynamic Number, Cryptogram Information Data, Application Cryptogram, Transaction Data Hash Code
        short offset = (short) 4;
        tmpBuffer[offset] = (byte) dynamicNumberLength;
        offset += (short) 1;

        arrayRandomFill(tag9f4cDynamicNumber);
        offset = Util.arrayCopyNonAtomic(tag9f4cDynamicNumber, (short) 0, tmpBuffer, offset, dynamicNumberLength);

        tmpBuffer[offset] = EmvTag.findTag((short) 0x9F27).getData()[0];
        offset += (short) 1;

        offset = Util.arrayCopyNonAtomic(applicationCryptogram.getData(), (short) 0, tmpBuffer, offset, (short) 8);

        // Transaction Data Hash Code: PDOL, CDOL1 and CDOL2 related data, and response data objects except 9F4B
        final short responseDataLength = responseTemplateGenerateAcCda.expandTlvToArray(buf, (short) 0, (short) 0x9F4B);

        shaMessageDigest.reset();
        if (pdolDataLength > 0) {
            shaMessageDigest.update(pdolData, (short) 0, pdolDataLength);
        }
        if (cdol1DataLength > 0) {
            shaMessageDigest.update(cdol1Data, (short) 0, cdol1DataLength);
        }
        if (secondGenerateAc && cdol2DataLength > 0) {
            shaMessageDigest.update(cdol2Data, (short) 0, cdol2DataLength);
        }
        shaMessageDigest.doFinal(buf, (short) 0, responseDataLength, tmpBuffer, offset);

        short checksumStartIndex = (short) (signedDataSize - 21);
        shaMessageDigest.reset();
        shaMessageDigest.update(tmpBuffer, (short) 1, (short) (checksumStartIndex - 1));
        shaMessageDigest.doFinal(unpredictableNumberSource, unpredictableNumberOffset, (short) 4, tmpBuffer, checksumStartIndex);

        signWithIccPrivateKey(buf);

        EmvTag.setTag((short) 0x9F4B, buf, (short) 0, (byte) signedDataSize);

        // CDA requires response format 2
        sendResponseTemplate(apdu, buf, responseTemplateGenerateAcCda, (short) 0x0077);
    }

    private void externalAuthenticate(APDU apdu, byte[] buf, short dataLength) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x00) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        // Allowed once, between ARQC and second GENERATE AC
        if (transactionState[OFFSET_STATE] != STATE_ARQC_ISSUED || transactionState[OFFSET_EXTERNAL_AUTHENTICATE_DONE] != (byte) 0x00) {
            EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        if (dataLength < (short) 8 || dataLength > (short) 16) {
            EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
        }

        transactionState[OFFSET_EXTERNAL_AUTHENTICATE_DONE] = (byte) 0x01;

        // Without Application Cryptogram Master Key, issuer authentication always succeeds
        if (isApplicationCryptogramMasterKeySet() && !verifyIssuerAuthenticationData(buf, ISO7816.OFFSET_CDATA, dataLength)) {
            transactionState[OFFSET_ISSUER_AUTHENTICATION_FAILED] = (byte) 0x01;
            EmvApplet.logAndThrow(SW_ISSUER_AUTHENTICATION_FAILED);
        }

        EmvApplet.logAndThrow(ISO7816.SW_NO_ERROR);
    }

    private void processGetData(APDU apdu, byte[] buf) {
        short tagId = Util.getShort(buf, ISO7816.OFFSET_P1);

        // EMV Book 3, 6.5.7 GET DATA: ATC, Last Online ATC Register, PIN Try Counter and Log Format
        switch (tagId) {
            case (short) 0x9F36:
            case (short) 0x9F13:
            case (short) 0x9F17:
            case (short) 0x9F4F:
                break;
            default:
                EmvApplet.logAndThrow(SW_REFERENCED_DATA_NOT_FOUND);
                break;
        }

        EmvTag tag = EmvTag.findTag(tagId);
        if (tag == null) {
            EmvApplet.logAndThrow(SW_REFERENCED_DATA_NOT_FOUND);
        }

        short dataLength = (short) (tag.copyToArray(buf, (short) ISO7816.OFFSET_CDATA) - ISO7816.OFFSET_CDATA);

        checkExpectedLength(buf, dataLength);

        sendResponse(apdu, buf, buf, (short) 0, dataLength);
    }

    private void processGetProcessingOptions(APDU apdu, byte[] buf, short dataLength) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x00) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        if (transactionState[OFFSET_STATE] != STATE_IDLE) {
            EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Command Template (tag 83) with PDOL related data
        if (dataLength < (short) 2 || buf[ISO7816.OFFSET_CDATA] != (byte) 0x83) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        short valueOffset = (short) (ISO7816.OFFSET_CDATA + 2);
        short valueLength = (short) (buf[(short) (ISO7816.OFFSET_CDATA + 1)] & 0x00FF);
        if (valueLength == (short) 0x81) {
            valueLength = (short) (buf[valueOffset] & 0x00FF);
            valueOffset += (short) 1;
        } else if (valueLength > (short) 0x7F) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        if ((short) (valueOffset - ISO7816.OFFSET_CDATA + valueLength) != dataLength) {
            EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
        }

        short expectedLength = findDataObjectListEntry((short) 0x9F38, (short) 0);
        if (expectedLength < 0) {
            expectedLength = (short) 0;
        }
        if (valueLength != expectedLength) {
            EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopyNonAtomic(buf, valueOffset, pdolData, (short) 0, valueLength);
        pdolDataLength = valueLength;
        cdol1DataLength = (short) 0;
        cdol2DataLength = (short) 0;

        incrementApplicationTransactionCounter();

        sendResponseTemplate(apdu, buf, responseTemplateGetProcessingOptions);

        transactionState[OFFSET_STATE] = STATE_GPO_DONE;
        transactionState[OFFSET_EXTERNAL_AUTHENTICATE_DONE] = (byte) 0x00;
        transactionState[OFFSET_ISSUER_AUTHENTICATION_FAILED] = (byte) 0x00;
    }

    /**
     * Raw RSA private key operation (signature) of tmpBuffer, result is written to dst in modulus length.
     */
    private void signWithIccPrivateKey(byte[] dst) {
        short signedDataSize = rsaPrivateKeyByteSize;

        // Raw RSA private key operation (signature). MODE_DECRYPT accepts full modulus length
        // input, MODE_ENCRYPT only allows modulus length - 1 bytes.
        // The MODE_ENCRYPT limit is a jcardsim (>= 3.0.6.0) deviation from the JavaCard spec for
        // ALG_RSA_NOPAD. Fix pending upstream: https://github.com/ph4r05/jcardsim/pull/3
        // Once merged and released, MODE_ENCRYPT could be used here again.
        rsaCipher.init(rsaPrivateKey, Cipher.MODE_DECRYPT);
        short signatureSize = rsaCipher.doFinal(tmpBuffer, (short) 0, signedDataSize, dst, (short) 0);

        // Result may have leading zero bytes stripped, left pad back to modulus length
        short padSize = (short) (signedDataSize - signatureSize);
        if (padSize > 0) {
            Util.arrayCopyNonAtomic(dst, (short) 0, dst, padSize, signatureSize);
            Util.arrayFillNonAtomic(dst, (short) 0, padSize, (byte) 0x00);
        }
    }

    private void processDynamicDataAuthentication(APDU apdu, byte[] buf, short dataLength) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x0000) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        requireRsaPrivateKey();

        // Without DDOL the terminal uses its Default DDOL, which the card does not know
        short expectedLength = findDataObjectListEntry((short) 0x9F49, (short) 0);
        if (expectedLength >= 0 && expectedLength != dataLength) {
            EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
        }

        short signedDataSize = rsaPrivateKeyByteSize;
        final short dynamicNumberLength = (short) tag9f4cDynamicNumber.length;

        // Build data to-be-encrypted

        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, signedDataSize, (byte) 0xBB);

        tmpBuffer[0] = (byte) 0x6A;
        tmpBuffer[1] = (byte) 0x05;
        tmpBuffer[2] = (byte) 0x01; // SHA-1 hash algo
        tmpBuffer[(short) (signedDataSize - 1)] = (byte) 0xBC;

        // ICC Dynamic Data: length of ICC Dynamic Number followed by ICC Dynamic Number
        tmpBuffer[3] = (byte) (dynamicNumberLength + 1);
        tmpBuffer[4] = (byte) dynamicNumberLength;
        arrayRandomFill(tag9f4cDynamicNumber);

        Util.arrayCopy(tag9f4cDynamicNumber, (short) 0, tmpBuffer, (short) 5, dynamicNumberLength);

        short checksumStartIndex = (short) (signedDataSize - 21);
        shaMessageDigest.reset();
        shaMessageDigest.update(tmpBuffer, (short) 1, (short) (checksumStartIndex - 1));
        shaMessageDigest.doFinal(buf, (short) ISO7816.OFFSET_CDATA, dataLength, tmpBuffer, checksumStartIndex);

        // Build Template

        signWithIccPrivateKey(buf);

        EmvTag.setTag((short) 0x9F4B, buf, (short) 0, (byte) signedDataSize);

        sendResponseTemplate(apdu, buf, responseTemplateDda);
    }

    private void processVerifyPin(APDU apdu, byte[] buf, short dataLength) {
        if (buf[ISO7816.OFFSET_P1] != (byte) 0x00) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        byte pinTypeQualifier = buf[ISO7816.OFFSET_P2];
        if (pinTypeQualifier != (byte) 0x80 && pinTypeQualifier != (byte) 0x88) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        byte pinTryCounter = getPinTryCounter();
        if (pinTryCounter <= (byte) 0) {
            EmvApplet.logAndThrow(SW_AUTHENTICATION_METHOD_BLOCKED);
        }

        byte[] givenPinBlock = buf;
        short givenPinBlockOffset = (short) ISO7816.OFFSET_CDATA;

        if (pinTypeQualifier == (byte) 0x80) {
            // Plaintext PIN block
            if (dataLength != (short) 8) {
                EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
            }
        } else {
            // Enciphered PIN block, EMV Book 2, 7.2 PIN Encipherment and Verification
            requireRsaPrivateKey();

            if (dataLength != rsaPrivateKeyByteSize) {
                EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
            }

            if (!challengeValid[0]) {
                EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            // ICC Unpredictable Number is valid for one verification only
            challengeValid[0] = false;

            rsaCipher.init(rsaPrivateKey, Cipher.MODE_DECRYPT);
            short plaintextLength = rsaCipher.doFinal(buf, ISO7816.OFFSET_CDATA, dataLength, tmpBuffer, (short) 0);

            if (plaintextLength != dataLength || tmpBuffer[0] != (byte) 0x7F) {
                EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
            }

            if (Util.arrayCompare(challenge, (short) 0, tmpBuffer, (short) 9, (short) challenge.length) != (byte) 0x00) {
                EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
            }

            givenPinBlock = tmpBuffer;
            givenPinBlockOffset = (short) 1;
        }

        if (Util.arrayCompare(givenPinBlock, givenPinBlockOffset, pinBlock, (short) 0, (short) pinBlock.length) != (byte) 0x00) {
            pinTryCounter -= (byte) 1;
            setPinTryCounter(pinTryCounter);

            if (pinTryCounter == (byte) 0) {
                EmvApplet.logAndThrow(SW_AUTHENTICATION_METHOD_BLOCKED);
            }

            EmvApplet.logAndThrow((short) (0x63C0 | pinTryCounter));
        }

        setPinTryCounter(PIN_TRY_LIMIT);

        EmvApplet.logAndThrow(ISO7816.SW_NO_ERROR);
    }

    private void arrayRandomFill(byte[] dst) {
        randomData.generateData(dst, (short) 0, (short) dst.length);
        if (!useRandom) {
            Util.arrayFillNonAtomic(dst, (short) 0, (short) dst.length, (byte) 0xAB);
        }
    }

    /**
     * Verify secure messaging format 1 command data field: optional data object followed by MAC data object '8E'
     * (EMV Book 2, 9.2 Secure Messaging for Integrity and Authentication, Annex D2).
     * MAC is computed with the MAC Session Key derived from MK_SMI and the Application Cryptogram of the first GENERATE AC over
     * chaining value || CLA INS P1 P2 || '80 00 00 00' || data object || padding.
     */
    private void verifySecureMessaging(byte[] buf, short dataLength) {
        final short end = (short) (ISO7816.OFFSET_CDATA + dataLength);
        short offset = (short) ISO7816.OFFSET_CDATA;

        // Plaintext ('81', 'B3') or enciphered ('87') command data object, odd tags are included in the MAC
        short dataObjectOffset = (short) -1;
        short dataObjectLength = (short) 0;
        if (offset < end && buf[offset] != (byte) 0x8E) {
            byte tag = buf[offset];
            if (tag != (byte) 0x81 && tag != (byte) 0x87 && tag != (byte) 0xB3) {
                EmvApplet.logAndThrow(SW_INCORRECT_SM_DATA_OBJECTS);
            }

            short headerLength = (short) 2;
            short valueLength = (short) ((short) (offset + 1) < end ? (buf[(short) (offset + 1)] & 0x00FF) : 0x00FF);
            if (valueLength == (short) 0x81 && (short) (offset + 2) < end) {
                headerLength = (short) 3;
                valueLength = (short) (buf[(short) (offset + 2)] & 0x00FF);
            } else if (valueLength > (short) 0x7F) {
                EmvApplet.logAndThrow(SW_INCORRECT_SM_DATA_OBJECTS);
            }

            dataObjectOffset = offset;
            dataObjectLength = (short) (headerLength + valueLength);
            offset += dataObjectLength;
        }

        if (offset >= end || buf[offset] != (byte) 0x8E) {
            EmvApplet.logAndThrow(SW_EXPECTED_SM_DATA_OBJECTS_MISSING);
        }

        short macLength = (short) ((short) (offset + 1) < end ? (buf[(short) (offset + 1)] & 0x00FF) : 0);
        short macOffset = (short) (offset + 2);
        if (macLength < (short) 4 || macLength > (short) 8 || (short) (macOffset + macLength) != end) {
            EmvApplet.logAndThrow(SW_INCORRECT_SM_DATA_OBJECTS);
        }

        deriveSessionKey(secureMessagingMacMasterKey, firstApplicationCryptogram, (short) 8);

        macInit();
        macUpdate(secureMessagingMacChain, (short) 0, (short) 8);
        macUpdate(buf, (short) ISO7816.OFFSET_CLA, (short) 4);
        if (dataObjectOffset >= 0) {
            Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) 4, (byte) 0x00);
            tmpBuffer[0] = (byte) 0x80;
            macUpdate(tmpBuffer, (short) 0, (short) 4);
            macUpdate(buf, dataObjectOffset, dataObjectLength);
        }
        // Full MAC is the chaining value of the next script command
        macFinal(secureMessagingMacChain, (short) 0);

        if (Util.arrayCompare(secureMessagingMacChain, (short) 0, buf, macOffset, macLength) != (byte) 0x00) {
            EmvApplet.logAndThrow(SW_INCORRECT_SM_DATA_OBJECTS);
        }
    }

    /**
     * Process issuer script command delivered after the first GENERATE AC (EMV Book 3, 10.10 Issuer-to-Card Script Processing).
     */
    private void processScriptCommand(APDU apdu, byte[] buf, short cmd, short dataLength) {
        if (transactionState[OFFSET_STATE] != STATE_ARQC_ISSUED && transactionState[OFFSET_STATE] != STATE_COMPLETED) {
            EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        if (!isKeySet(secureMessagingMacMasterKey)) {
            EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        verifySecureMessaging(buf, dataLength);

        short p1p2 = Util.getShort(buf, ISO7816.OFFSET_P1);
        switch (cmd) {
            // EMV Book 3, 6.5.1
            case CMD_APPLICATION_BLOCK:
                if (p1p2 != (short) 0x0000) {
                    EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
                }
                applicationBlocked = true;
                break;
            // EMV Book 3, 6.5.2
            case CMD_APPLICATION_UNBLOCK:
                if (p1p2 != (short) 0x0000) {
                    EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
                }
                applicationBlocked = false;
                break;
            // EMV Book 3, 6.5.3
            case CMD_CARD_BLOCK:
                if (p1p2 != (short) 0x0000) {
                    EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
                }
                cardBlocked = true;
                break;
            // EMV Book 3, 6.5.10, P2 '01' and '02' (PIN change) are reserved for payment systems
            case CMD_PIN_CHANGE_UNBLOCK:
                if (p1p2 != (short) 0x0000) {
                    EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
                }
                setPinTryCounter(PIN_TRY_LIMIT);
                break;
            // Payment system specific commands, placeholders that accept the command without changing data
            case CMD_PUT_DATA:
            case CMD_PUT_DATA_PROPRIETARY:
            case CMD_UPDATE_RECORD:
            case CMD_UPDATE_RECORD_PROPRIETARY:
            default:
                break;
        }

        EmvApplet.logAndThrow(ISO7816.SW_NO_ERROR);
    }

    private void processGetChallenge(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x00) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        short outputLength = (short) challenge.length;

        checkExpectedLength(buf, outputLength);

        arrayRandomFill(challenge);
        challengeValid[0] = true;

        sendResponse(apdu, buf, challenge, (short) 0, outputLength);
    }

    protected void processCommand(APDU apdu, byte[] buf, short cmd, short dataLength) {
        switch (cmd) {
            case CMD_READ_RECORD:
                processReadRecord(apdu, buf);
                break;
            case CMD_DDA:
                processDynamicDataAuthentication(apdu, buf, dataLength);
                break;
            case CMD_VERIFY_PIN:
                processVerifyPin(apdu, buf, dataLength);
                break;
            case CMD_GET_CHALLENGE:
                processGetChallenge(apdu, buf);
                break;
            case CMD_GET_DATA:
                processGetData(apdu, buf);
                break;
            case CMD_GET_PROCESSING_OPTIONS:
                processGetProcessingOptions(apdu, buf, dataLength);
                break;
            case CMD_GENERATE_AC:
                processGenerateAc(apdu, buf, dataLength);
                break;
            case CMD_EXTERNAL_AUTHENTICATE:
                externalAuthenticate(apdu, buf, dataLength);
                break;
            case CMD_APPLICATION_BLOCK:
            case CMD_APPLICATION_UNBLOCK:
            case CMD_CARD_BLOCK:
            case CMD_PIN_CHANGE_UNBLOCK:
            case CMD_PUT_DATA:
            case CMD_PUT_DATA_PROPRIETARY:
            case CMD_UPDATE_RECORD:
            case CMD_UPDATE_RECORD_PROPRIETARY:
                processScriptCommand(apdu, buf, cmd, dataLength);
                break;
            default:
                commandNotSupported(cmd);
        }
    }
}
