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
    private static final short OFFSET_RELAY_RESISTANCE_PERFORMED = (short) 3;
    // Card Verification Results related events of the transaction, see TXN_*
    private static final short OFFSET_TRANSACTION_EVENTS = (short) 4;
    // Cryptogram Information Data of the first and the second GENERATE AC
    private static final short OFFSET_FIRST_CRYPTOGRAM_TYPE = (short) 5;
    private static final short OFFSET_SECOND_CRYPTOGRAM_TYPE = (short) 6;
    // Card risk management results of the transaction, see CRM_*
    private static final short OFFSET_RISK_EVENTS = (short) 7;
    // Card risk management state and script command count of previous transactions, at the start of the transaction
    private static final short OFFSET_PREVIOUS_RISK_STATE = (short) 8;
    private static final short OFFSET_PREVIOUS_SCRIPT_COMMAND_COUNT = (short) 9;
    private static final short TRANSACTION_STATE_LENGTH = (short) 10;

    private static final byte TXN_OFFLINE_PIN_PERFORMED = (byte) 0x01;
    private static final byte TXN_OFFLINE_PIN_FAILED = (byte) 0x02;
    private static final byte TXN_DDA_PERFORMED = (byte) 0x04;
    private static final byte TXN_CDA_PERFORMED = (byte) 0x08;
    private static final byte TXN_ISSUER_AUTHENTICATION_PERFORMED = (byte) 0x10;
    private static final byte TXN_UNABLE_TO_GO_ONLINE = (byte) 0x20;
    private static final byte TXN_SCRIPT_RECEIVED = (byte) 0x40;
    private static final byte TXN_LOGGED = (byte) 0x80;

    // Same bit positions as in Common Core Definitions CVR byte 3
    private static final byte CRM_LOWER_COUNT_EXCEEDED = (byte) 0x80;
    private static final byte CRM_UPPER_COUNT_EXCEEDED = (byte) 0x40;
    private static final byte CRM_LOWER_AMOUNT_EXCEEDED = (byte) 0x20;
    private static final byte CRM_UPPER_AMOUNT_EXCEEDED = (byte) 0x10;

    // Card risk management state kept over transactions
    private static final byte RISK_LAST_ONLINE_NOT_COMPLETED = (byte) 0x01;
    private static final byte RISK_GO_ONLINE_NEXT = (byte) 0x02;
    private static final byte RISK_ISSUER_AUTHENTICATION_FAILED = (byte) 0x04;
    private static final byte RISK_SDA_FAILED = (byte) 0x08;
    private static final byte RISK_DDA_FAILED = (byte) 0x10;
    private static final byte RISK_SCRIPT_FAILED = (byte) 0x20;

    // Card Verification Results formats in Issuer Application Data
    private static final byte CVR_FORMAT_NONE = (byte) 0x00;
    // Common Core Definitions CVR, 5 bytes (EMV Book 3, Annex C7.3)
    private static final byte CVR_FORMAT_CCD = (byte) 0x01;
    // Visa CVR, length byte '03' followed by 3 bytes
    private static final byte CVR_FORMAT_VISA = (byte) 0x02;

    // Authorisation Response Codes 'Y3' and 'Z3': unable to go online, offline approved or declined
    private static final short ARC_UNABLE_TO_GO_ONLINE_APPROVED = (short) 0x5933;
    private static final short ARC_UNABLE_TO_GO_ONLINE_DECLINED = (short) 0x5A33;

    private static final short AMOUNT_LENGTH = (short) 6;

    // Default COMPUTE CRYPTOGRAPHIC CHECKSUM response: CVC3 Track2 (9F61), CVC3 Track1 (9F60), ATC (9F36)
    private static final byte[] DEFAULT_COMPUTE_CRYPTOGRAPHIC_CHECKSUM_TEMPLATE = {
        (byte) 0x9F, (byte) 0x61, (byte) 0x9F, (byte) 0x60, (byte) 0x9F, (byte) 0x36
    };

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
    // MAC chaining value of issuer script commands with secure messaging format 1 (EMV Book 2, 9.2.3.1)
    private byte[] secureMessagingMacChain;
    // MAC length of issuer script commands with secure messaging format 2, the data field has no MAC data object to give it
    private static final short SECURE_MESSAGING_FORMAT_2_MAC_LENGTH = (short) 8;
    // APPLICATION BLOCK state (EMV Book 3, 6.5.1)
    private boolean applicationBlocked = false;

    // Relay Resistance Protocol (EMV Contactless Book C-2, 3.10 and 5.3)
    private static final short RELAY_RESISTANCE_ENTROPY_LENGTH = (short) 4;
    private static final short RELAY_RESISTANCE_TIMING_LENGTH = (short) 6;
    private static final short RELAY_RESISTANCE_DATA_LENGTH = (short) (2 * RELAY_RESISTANCE_ENTROPY_LENGTH + RELAY_RESISTANCE_TIMING_LENGTH);
    // Min Time For Processing Relay Resistance APDU (DF8303), Max Time For Processing Relay Resistance APDU (DF8304) and
    // Device Estimated Transmission Time For Relay Resistance R-APDU (DF8305), in units of hundreds of microseconds
    private byte[] relayResistanceTiming;
    // Terminal Relay Resistance Entropy (DF8301) || Device Relay Resistance Entropy (DF8302) || timing, signed in CDA
    private byte[] relayResistanceData;

    // Separate ICC PIN Encipherment private key (EMV Book 2, 7.1), ICC private key is used when not set
    private RSAPrivateKey pinRsaPrivateKey = null;
    private short pinRsaPrivateKeyByteSize = 0;

    // Card risk management (EMV Book 3, Annex C Common Core Definitions)
    private boolean cardRiskManagement = false;
    private byte cvrFormat = CVR_FORMAT_NONE;
    private short cvrOffset = 0;
    private short consecutiveOfflineTransactions = 0;
    private byte[] cumulativeOfflineAmount;
    // Lower Cumulative Offline Transaction Amount (6) || Upper Cumulative Offline Transaction Amount (6), zero is no limit
    private byte[] cumulativeOfflineAmountLimits;
    private byte riskState = 0;
    private byte lastScriptCommandCount = 0;

    // Transaction log (EMV Book 3, Annex D)
    private TransactionLog transactionLog;

    // qVSDC: Application Cryptogram in GET PROCESSING OPTIONS response (EMV Contactless Book C-3)
    private boolean cryptogramInGetProcessingOptions = false;
    private byte[] foundTransactionData;
    private short foundTransactionDataOffset = 0;

    // Mag-stripe mode CVC3 (EMV Contactless Book C-2, COMPUTE CRYPTOGRAPHIC CHECKSUM)
    private DESKey cvc3Key = null;
    // IVCVC3 Track1 (2) || IVCVC3 Track2 (2)
    private byte[] cvc3InitializationVectors;
    private TagTemplate responseTemplateComputeCryptographicChecksum;

    // Torn transaction recovery with RECOVER AC (EMV Contactless Book C-2, 5.6)
    private byte[] recoverableResponse;
    private short recoverableResponseLength = 0;
    private byte[] recoverableDrdolData;
    private short recoverableDrdolDataLength = 0;
    private boolean captureRecoverableResponse = false;

    // Tags that the terminal may write with PUT DATA without secure messaging (EMV Contactless Book C-2, 5.5), tag entries
    private TagTemplate putDataTags;

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
                cryptogramInGetProcessingOptions = ((flags & (1 << 2)) != 0);
                cardRiskManagement = ((flags & (1 << 3)) != 0);
                break;
            // ICC RSA KEY MODULUS
            case 0x0004:
                rsaPrivateKeyByteSize = dataLength;
                rsaPrivateKey = buildRsaPrivateKey(buf, dataLength);
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
            // RELAY RESISTANCE TIMING: Min Time For Processing Relay Resistance APDU (2), Max Time For Processing Relay Resistance APDU (2),
            // Device Estimated Transmission Time For Relay Resistance R-APDU (2)
            case 0x000A:
                if (dataLength != RELAY_RESISTANCE_TIMING_LENGTH) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                Util.arrayCopy(buf, (short) ISO7816.OFFSET_CDATA, relayResistanceTiming, (short) 0, RELAY_RESISTANCE_TIMING_LENGTH);
                break;
            // ICC CVC3 KEY KD_CVC3 (double length Triple DES) for mag-stripe mode, empty data clears the key
            case 0x000B:
                cvc3Key = setMasterKey(cvc3Key, buf, dataLength);
                break;
            // IVCVC3 TRACK1 (2) || IVCVC3 TRACK2 (2)
            case 0x000C:
                if (dataLength != (short) 4) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                Util.arrayCopy(buf, (short) ISO7816.OFFSET_CDATA, cvc3InitializationVectors, (short) 0, (short) 4);
                break;
            // CARD VERIFICATION RESULTS: format (1) || offset of the CVR in Issuer Application Data (1)
            case 0x000D:
                if (dataLength != (short) 2) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                if (buf[ISO7816.OFFSET_CDATA] != CVR_FORMAT_NONE && buf[ISO7816.OFFSET_CDATA] != CVR_FORMAT_CCD
                    && buf[ISO7816.OFFSET_CDATA] != CVR_FORMAT_VISA) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                cvrFormat = buf[ISO7816.OFFSET_CDATA];
                cvrOffset = (short) (buf[(short) (ISO7816.OFFSET_CDATA + 1)] & 0x00FF);
                break;
            // CUMULATIVE OFFLINE TRANSACTION AMOUNT LIMITS: lower (6) || upper (6), n12 like Amount, Authorised
            case 0x000E:
                if (dataLength != (short) (2 * AMOUNT_LENGTH)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                Util.arrayCopy(buf, (short) ISO7816.OFFSET_CDATA, cumulativeOfflineAmountLimits, (short) 0, (short) (2 * AMOUNT_LENGTH));
                break;
            // ICC PIN ENCIPHERMENT RSA KEY MODULUS, empty data clears the key
            case 0x000F:
                if (dataLength == (short) 0) {
                    pinRsaPrivateKey = null;
                    pinRsaPrivateKeyByteSize = (short) 0;
                    break;
                }
                pinRsaPrivateKeyByteSize = dataLength;
                pinRsaPrivateKey = buildRsaPrivateKey(buf, dataLength);
                break;
            // ICC PIN ENCIPHERMENT RSA KEY PRIVATE EXPONENT
            case 0x0010:
                if (pinRsaPrivateKey == null) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                pinRsaPrivateKey.setExponent(buf, (short) ISO7816.OFFSET_CDATA, dataLength);
                break;
            // PUT DATA TAGS: tag entries that the terminal may write with PUT DATA, e.g. Data Storage or balance
            case 0x0011:
                putDataTags.setData(buf, (short) ISO7816.OFFSET_CDATA, (byte) dataLength);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * Build RSA private key with the modulus from command data.
     */
    private static RSAPrivateKey buildRsaPrivateKey(byte[] buf, short modulusLength) {
        short keyLength = (short) (modulusLength * 8);
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
        RSAPrivateKey key = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keyLength, false);
        key.clearKey();

        key.setModulus(buf, (short) ISO7816.OFFSET_CDATA, modulusLength);

        return key;
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

        // Called also from the EmvApplet constructor, before the fields of this class are initialized
        consecutiveOfflineTransactions = (short) 0;
        riskState = (byte) 0;
        lastScriptCommandCount = (byte) 0;
        recoverableResponseLength = (short) 0;
        recoverableDrdolDataLength = (short) 0;
        if (cumulativeOfflineAmount != null) {
            Util.arrayFillNonAtomic(cumulativeOfflineAmount, (short) 0, AMOUNT_LENGTH, (byte) 0x00);
        }
        if (transactionLog != null) {
            transactionLog.clear();
        }
    }

    protected PaymentApplication(byte[] buffer, short offset, byte length) {
        super();

        // Default PIN 0000 as plaintext PIN block (EMV Book 3, 6.5.12)
        pinBlock = new byte[] { (byte) 0x24, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };

        challenge = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        challengeValid = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_DESELECT);

        tag9f4cDynamicNumber = JCSystem.makeTransientByteArray((short) 3, JCSystem.CLEAR_ON_DESELECT);

        transactionState = JCSystem.makeTransientByteArray(TRANSACTION_STATE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        firstApplicationCryptogram = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        secureMessagingMacChain = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        relayResistanceData = JCSystem.makeTransientByteArray(RELAY_RESISTANCE_DATA_LENGTH, JCSystem.CLEAR_ON_DESELECT);

        // Default timing: min 0.0 ms, max 20.0 ms, estimated transmission time 1.8 ms
        relayResistanceTiming = new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xC8, (byte) 0x00, (byte) 0x12 };

        pdolData = new byte[255];
        cdol1Data = new byte[255];
        cdol2Data = new byte[255];

        responseTemplateGenerateAcCda = new TagTemplate();
        responseTemplateComputeCryptographicChecksum = new TagTemplate();
        responseTemplateComputeCryptographicChecksum.setData(DEFAULT_COMPUTE_CRYPTOGRAPHIC_CHECKSUM_TEMPLATE, (short) 0,
            (byte) DEFAULT_COMPUTE_CRYPTOGRAPHIC_CHECKSUM_TEMPLATE.length);
        putDataTags = new TagTemplate();

        cumulativeOfflineAmount = new byte[AMOUNT_LENGTH];
        cumulativeOfflineAmountLimits = new byte[(short) (2 * AMOUNT_LENGTH)];
        transactionLog = new TransactionLog();
        cvc3InitializationVectors = new byte[4];
        recoverableResponse = new byte[RESPONSE_BUFFER_SIZE];
        recoverableDrdolData = new byte[255];

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

        // Check if PAN (tag 5A) exists in the ICC
        if (EmvTag.findTag((short) 0x5A) != null) {
            expandFciTemplate(tagBf0cFci, (short) 0xBF0C);
            expandFciTemplate(tagA5Fci, (short) 0xA5);
            expandFciTemplate(tag6fFci, (short) 0x6F);

            sendResponse(apdu, buf, (short) 0x6F);
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

    /**
     * Find a data object from the DOL related data of the transaction, CDOL2 first, then CDOL1 and PDOL.
     * Value is at foundTransactionData[foundTransactionDataOffset] and its length in dataObjectListEntryLength.
     */
    private boolean findTransactionData(short tagId) {
        return findTransactionData((short) 0x008D, cdol2Data, cdol2DataLength, tagId)
            || findTransactionData((short) 0x008C, cdol1Data, cdol1DataLength, tagId)
            || findTransactionData((short) 0x9F38, pdolData, pdolDataLength, tagId);
    }

    private boolean findTransactionData(short dolTagId, byte[] dolData, short dolDataLength, short tagId) {
        if (dolDataLength <= (short) 0) {
            return false;
        }

        short offset = findDataObjectListEntry(dolTagId, tagId);
        if (offset < 0 || (short) (offset + dataObjectListEntryLength) > dolDataLength) {
            return false;
        }

        foundTransactionData = dolData;
        foundTransactionDataOffset = offset;
        return true;
    }

    /**
     * Build DOL related data for the DOL stored in tag dolTagId, like a terminal does (EMV Book 3, 5.4).
     * Values are taken from the DOL related data of the transaction or from the card data, missing values are zero filled.
     * Returns the end offset in dst, or dstOffset if the DOL does not exist.
     */
    private short buildDataObjectListData(short dolTagId, byte[] dst, short dstOffset) {
        EmvTag dolTag = EmvTag.findTag(dolTagId);
        if (dolTag == null) {
            return dstOffset;
        }

        byte[] dol = dolTag.getData();
        short dolLength = (short) (dolTag.getLength() & 0x00FF);
        short offset = dstOffset;

        short i = (short) 0;
        while (i < dolLength) {
            short tagLength = EmvTag.tagEntryLength(dol, i);
            if ((short) (i + tagLength) >= dolLength) {
                break;
            }
            short valueLength = (short) (dol[(short) (i + tagLength)] & 0x00FF);

            short tagId = (short) 0;
            if (tagLength == (short) 1) {
                tagId = (short) (dol[i] & 0x00FF);
            } else if (tagLength == (short) 2) {
                tagId = Util.getShort(dol, i);
            }

            Util.arrayFillNonAtomic(dst, offset, valueLength, (byte) 0x00);
            if (tagId != (short) 0 && findTransactionData(tagId)) {
                short copyLength = dataObjectListEntryLength < valueLength ? dataObjectListEntryLength : valueLength;
                Util.arrayCopyNonAtomic(foundTransactionData, foundTransactionDataOffset, dst, offset, copyLength);
            } else {
                EmvTag tag = EmvTag.findTag(dol, i);
                if (tag != null) {
                    short tagDataLength = (short) (tag.getLength() & 0x00FF);
                    short copyLength = tagDataLength < valueLength ? tagDataLength : valueLength;
                    Util.arrayCopyNonAtomic(tag.getData(), (short) 0, dst, offset, copyLength);
                }
            }

            offset += valueLength;
            i += (short) (tagLength + 1);
        }

        return offset;
    }

    private void setTransactionEvent(byte event) {
        transactionState[OFFSET_TRANSACTION_EVENTS] |= event;
    }

    private boolean isTransactionEvent(byte event) {
        return (transactionState[OFFSET_TRANSACTION_EVENTS] & event) != 0;
    }

    private void setRiskState(byte flag, boolean value) {
        if (value) {
            riskState |= flag;
        } else {
            riskState &= (byte) ~flag;
        }
    }

    private boolean isRiskState(byte flag) {
        return (riskState & flag) != 0;
    }

    /**
     * Card risk management state of previous transactions, as it was at the start of this transaction.
     */
    private boolean isPreviousRiskState(byte flag) {
        return (transactionState[OFFSET_PREVIOUS_RISK_STATE] & flag) != 0;
    }

    /**
     * Amount, Authorised of the transaction is counted in the offline amounts only in the Application Currency Code (EMV Book 3, Annex C).
     * Returns false if the amount is not available.
     */
    private boolean findTransactionAmount() {
        EmvTag applicationCurrencyCode = EmvTag.findTag((short) 0x9F42);
        if (applicationCurrencyCode != null && applicationCurrencyCode.getLength() == (byte) 2 && findTransactionData((short) 0x5F2A)
            && dataObjectListEntryLength == (short) 2
            && Util.arrayCompare(foundTransactionData, foundTransactionDataOffset, applicationCurrencyCode.getData(), (short) 0, (short) 2) != 0) {
            return false;
        }

        return findTransactionData((short) 0x9F02) && dataObjectListEntryLength == AMOUNT_LENGTH;
    }

    /**
     * Add or subtract packed BCD numbers left and right of the same length to dst, subtraction result is at least zero.
     */
    private static void bcdAddOrSubtract(byte[] left, short leftOffset, byte[] right, short rightOffset, byte[] dst, short dstOffset,
        short length, boolean subtract) {
        if (subtract && Util.arrayCompare(left, leftOffset, right, rightOffset, length) < 0) {
            Util.arrayFillNonAtomic(dst, dstOffset, length, (byte) 0x00);
            return;
        }

        short carry = (short) 0;
        for (short i = (short) (length - 1); i >= 0; i--) {
            short result = (short) 0;
            for (short shift = (short) 0; shift <= (short) 4; shift += (short) 4) {
                short leftDigit = (short) ((left[(short) (leftOffset + i)] >> shift) & 0x0F);
                short rightDigit = (short) ((right[(short) (rightOffset + i)] >> shift) & 0x0F);
                short digit = subtract ? (short) (leftDigit - rightDigit - carry) : (short) (leftDigit + rightDigit + carry);
                carry = (short) 0;
                if (digit < 0) {
                    digit += (short) 10;
                    carry = (short) 1;
                } else if (digit > (short) 9) {
                    digit -= (short) 10;
                    carry = (short) 1;
                }
                result |= (short) (digit << shift);
            }
            dst[(short) (dstOffset + i)] = (byte) result;
        }

        // Addition overflow saturates to the maximum value
        if (carry != 0 && !subtract) {
            Util.arrayFillNonAtomic(dst, dstOffset, length, (byte) 0x99);
        }
    }

    private static boolean isZero(byte[] src, short offset, short length) {
        for (short i = (short) 0; i < length; i++) {
            if (src[(short) (offset + i)] != (byte) 0x00) {
                return false;
            }
        }
        return true;
    }

    /**
     * True if cumulative offline amount with the transaction amount exceeds the limit at limitOffset, zero limit is no limit.
     */
    private boolean isCumulativeAmountLimitExceeded(short limitOffset) {
        if (isZero(cumulativeOfflineAmountLimits, limitOffset, AMOUNT_LENGTH) || !findTransactionAmount()) {
            return false;
        }

        bcdAddOrSubtract(cumulativeOfflineAmount, (short) 0, foundTransactionData, foundTransactionDataOffset, tmpBuffer, (short) 0,
            AMOUNT_LENGTH, false);
        return Util.arrayCompare(tmpBuffer, (short) 0, cumulativeOfflineAmountLimits, limitOffset, AMOUNT_LENGTH) > 0;
    }

    /**
     * True if the consecutive offline transactions with this transaction exceed the limit in tag limitTagId.
     */
    private boolean isConsecutiveOfflineLimitExceeded(short limitTagId) {
        EmvTag limit = EmvTag.findTag(limitTagId);
        return limit != null && limit.getLength() == (byte) 1 && consecutiveOfflineTransactions >= (short) (limit.getData()[0] & 0x00FF);
    }

    /**
     * True if Offline Accumulator Balance (tag 9F50) does not cover the transaction amount.
     */
    private boolean isBalanceInsufficient() {
        EmvTag balance = EmvTag.findTag((short) 0x9F50);
        return balance != null && balance.getLength() == (byte) AMOUNT_LENGTH && findTransactionAmount()
            && Util.arrayCompare(balance.getData(), (short) 0, foundTransactionData, foundTransactionDataOffset, AMOUNT_LENGTH) < 0;
    }

    /**
     * Check lower (online) or upper (offline) velocity limits, returns true if any is exceeded.
     */
    private boolean checkVelocityLimits(boolean upper) {
        byte exceeded = (byte) 0;
        if (upper) {
            if (isConsecutiveOfflineLimitExceeded((short) 0x9F23)) {
                exceeded |= CRM_UPPER_COUNT_EXCEEDED;
            }
            if (isCumulativeAmountLimitExceeded(AMOUNT_LENGTH)) {
                exceeded |= CRM_UPPER_AMOUNT_EXCEEDED;
            }
        } else {
            if (isConsecutiveOfflineLimitExceeded((short) 0x9F14)) {
                exceeded |= CRM_LOWER_COUNT_EXCEEDED;
            }
            if (isCumulativeAmountLimitExceeded((short) 0)) {
                exceeded |= CRM_LOWER_AMOUNT_EXCEEDED;
            }
        }

        transactionState[OFFSET_RISK_EVENTS] |= exceeded;
        return exceeded != (byte) 0;
    }

    /**
     * Card risk management of an offline approval request (EMV Book 3, Annex C Common Core Definitions, card action analysis).
     * Returns ARQC when the transaction should go online.
     */
    private byte cardRiskManagementOfflineRequest() {
        boolean goOnline = checkVelocityLimits(false);
        goOnline |= isBalanceInsufficient();
        goOnline |= isRiskState((byte) (RISK_GO_ONLINE_NEXT | RISK_LAST_ONLINE_NOT_COMPLETED));

        if (!cardRiskManagement) {
            return CID_TC;
        }
        return goOnline ? CID_ARQC : CID_TC;
    }

    /**
     * Card risk management when the terminal is unable to go online, returns AAC when upper limits are exceeded.
     */
    private byte cardRiskManagementUnableToGoOnline() {
        checkVelocityLimits(false);
        boolean decline = checkVelocityLimits(true);

        if (!cardRiskManagement) {
            return CID_TC;
        }
        return decline ? CID_AAC : CID_TC;
    }

    /**
     * Update counters after an offline approval: consecutive offline transactions, cumulative offline amount and balance.
     */
    private void recordOfflineApproval() {
        if (consecutiveOfflineTransactions < (short) 0x7FFF) {
            consecutiveOfflineTransactions++;
        }

        if (!findTransactionAmount()) {
            return;
        }

        bcdAddOrSubtract(cumulativeOfflineAmount, (short) 0, foundTransactionData, foundTransactionDataOffset, cumulativeOfflineAmount,
            (short) 0, AMOUNT_LENGTH, false);

        EmvTag balance = EmvTag.findTag((short) 0x9F50);
        if (balance != null && balance.getLength() == (byte) AMOUNT_LENGTH) {
            bcdAddOrSubtract(balance.getData(), (short) 0, foundTransactionData, foundTransactionDataOffset, balance.getData(), (short) 0,
                AMOUNT_LENGTH, true);
        }
    }

    /**
     * Reset counters after an online approval with successful issuer authentication, Last Online ATC Register is the ATC.
     */
    private void recordOnlineApproval() {
        consecutiveOfflineTransactions = (short) 0;
        Util.arrayFillNonAtomic(cumulativeOfflineAmount, (short) 0, AMOUNT_LENGTH, (byte) 0x00);
        setRiskState((byte) (RISK_GO_ONLINE_NEXT | RISK_ISSUER_AUTHENTICATION_FAILED | RISK_SDA_FAILED | RISK_DDA_FAILED), false);

        EmvTag applicationTransactionCounter = EmvTag.findTag((short) 0x9F36);
        if (applicationTransactionCounter != null) {
            EmvTag.setTag((short) 0x9F13, applicationTransactionCounter.getData(), (short) 0, applicationTransactionCounter.getLength());
        }
    }

    /**
     * Remember offline data authentication failure indicated by the terminal in TVR when the transaction is declined offline.
     */
    private void recordOfflineDataAuthenticationResult() {
        if (!findTransactionData((short) 0x0095) || dataObjectListEntryLength < (short) 1) {
            return;
        }

        byte tvr = foundTransactionData[foundTransactionDataOffset];
        // TVR byte 1: b7 SDA failed, b4 DDA failed, b3 CDA failed
        setRiskState(RISK_SDA_FAILED, (tvr & (byte) 0x40) != 0);
        setRiskState(RISK_DDA_FAILED, (tvr & (byte) 0x0C) != 0);
    }

    /**
     * Cryptogram type bits of CVR: '00' AAC, '01' TC, '10' ARQC or second GENERATE AC not requested.
     */
    private static byte cvrCryptogramType(byte cid) {
        switch (cid) {
            case CID_TC:
                return (byte) 0x01;
            case CID_ARQC:
                return (byte) 0x02;
            default:
                return (byte) 0x00;
        }
    }

    /**
     * Update Card Verification Results in Issuer Application Data (tag 9F10) at the configured offset.
     */
    private void updateCardVerificationResults() {
        if (cvrFormat == CVR_FORMAT_NONE) {
            return;
        }

        EmvTag issuerApplicationData = EmvTag.findTag((short) 0x9F10);
        short cvrLength = cvrFormat == CVR_FORMAT_CCD ? (short) 5 : (short) 4;
        if (issuerApplicationData == null || (short) (cvrOffset + cvrLength) > (short) (issuerApplicationData.getLength() & 0x00FF)) {
            return;
        }

        byte firstType = cvrCryptogramType(transactionState[OFFSET_FIRST_CRYPTOGRAM_TYPE]);
        byte secondType = transactionState[OFFSET_STATE] == STATE_ARQC_ISSUED
            ? cvrCryptogramType(transactionState[OFFSET_SECOND_CRYPTOGRAM_TYPE]) : (byte) 0x02;
        final boolean online = transactionState[OFFSET_FIRST_CRYPTOGRAM_TYPE] == CID_ARQC && !isTransactionEvent(TXN_UNABLE_TO_GO_ONLINE);
        final boolean completed = transactionState[OFFSET_STATE] == STATE_ARQC_ISSUED;
        final boolean issuerAuthenticationFailed = transactionState[OFFSET_ISSUER_AUTHENTICATION_FAILED] != (byte) 0x00;
        final boolean issuerAuthenticationNotPerformed = online && completed && !isTransactionEvent(TXN_ISSUER_AUTHENTICATION_PERFORMED);
        final byte pinTryCounter = getPinTryCounter();
        final byte riskEvents = transactionState[OFFSET_RISK_EVENTS];
        // Script command count is limited to 15 when counted, see processScriptCommand
        final byte scripts = transactionState[OFFSET_PREVIOUS_SCRIPT_COMMAND_COUNT];

        byte[] cvr = tmpBuffer;
        Util.arrayFillNonAtomic(cvr, (short) 0, cvrLength, (byte) 0x00);

        if (cvrFormat == CVR_FORMAT_CCD) {
            cvr[0] = (byte) ((secondType << 6) | (firstType << 4));
            cvr[0] |= isTransactionEvent(TXN_CDA_PERFORMED) ? (byte) 0x08 : 0;
            cvr[0] |= isTransactionEvent(TXN_DDA_PERFORMED) ? (byte) 0x04 : 0;
            cvr[0] |= issuerAuthenticationNotPerformed ? (byte) 0x02 : 0;
            cvr[0] |= issuerAuthenticationFailed ? (byte) 0x01 : 0;

            cvr[1] = (byte) ((pinTryCounter & 0x0F) << 4);
            cvr[1] |= isTransactionEvent(TXN_OFFLINE_PIN_PERFORMED) ? (byte) 0x08 : 0;
            cvr[1] |= isTransactionEvent(TXN_OFFLINE_PIN_FAILED) ? (byte) 0x04 : 0;
            cvr[1] |= pinTryCounter == (byte) 0 ? (byte) 0x02 : 0;
            cvr[1] |= isPreviousRiskState(RISK_LAST_ONLINE_NOT_COMPLETED) ? (byte) 0x01 : 0;

            cvr[2] = (byte) (riskEvents & (byte) 0xF0);

            cvr[3] = (byte) (scripts << 4);
            cvr[3] |= isPreviousRiskState(RISK_SCRIPT_FAILED) ? (byte) 0x08 : 0;
            cvr[3] |= isPreviousRiskState((byte) (RISK_SDA_FAILED | RISK_DDA_FAILED)) ? (byte) 0x04 : 0;
            cvr[3] |= isPreviousRiskState(RISK_GO_ONLINE_NEXT) ? (byte) 0x02 : 0;
            cvr[3] |= isTransactionEvent(TXN_UNABLE_TO_GO_ONLINE) ? (byte) 0x01 : 0;
        } else {
            cvr[0] = (byte) 0x03;

            cvr[1] = (byte) ((secondType << 6) | (firstType << 4));
            cvr[1] |= issuerAuthenticationFailed ? (byte) 0x08 : 0;
            cvr[1] |= isTransactionEvent(TXN_OFFLINE_PIN_PERFORMED) ? (byte) 0x04 : 0;
            cvr[1] |= isTransactionEvent(TXN_OFFLINE_PIN_FAILED) ? (byte) 0x02 : 0;
            cvr[1] |= isTransactionEvent(TXN_UNABLE_TO_GO_ONLINE) ? (byte) 0x01 : 0;

            final EmvTag lastOnlineAtc = EmvTag.findTag((short) 0x9F13);
            cvr[2] = isPreviousRiskState(RISK_LAST_ONLINE_NOT_COMPLETED) ? (byte) 0x80 : 0;
            cvr[2] |= pinTryCounter == (byte) 0 ? (byte) 0x40 : 0;
            cvr[2] |= riskEvents != (byte) 0 ? (byte) 0x20 : 0;
            cvr[2] |= (lastOnlineAtc == null || isZero(lastOnlineAtc.getData(), (short) 0, (short) (lastOnlineAtc.getLength() & 0x00FF)))
                ? (byte) 0x10 : 0;
            cvr[2] |= isPreviousRiskState(RISK_ISSUER_AUTHENTICATION_FAILED) ? (byte) 0x08 : 0;
            cvr[2] |= issuerAuthenticationNotPerformed ? (byte) 0x04 : 0;
            cvr[2] |= isPreviousRiskState(RISK_SDA_FAILED) ? (byte) 0x01 : 0;

            cvr[3] = (byte) (scripts << 4);
            cvr[3] |= isPreviousRiskState(RISK_SCRIPT_FAILED) ? (byte) 0x08 : 0;
            cvr[3] |= isPreviousRiskState(RISK_DDA_FAILED) ? (byte) 0x04 : 0;
            cvr[3] |= isTransactionEvent((byte) (TXN_DDA_PERFORMED | TXN_CDA_PERFORMED)) ? (byte) 0x02 : 0;
        }

        Util.arrayCopyNonAtomic(cvr, (short) 0, issuerApplicationData.getData(), cvrOffset, cvrLength);
    }

    /**
     * Add or update the transaction log record of this transaction when Log Entry (9F4D) and Log Format (9F4F) exist.
     */
    private void logTransaction() {
        EmvTag logEntry = EmvTag.findTag((short) 0x9F4D);
        if (logEntry == null || logEntry.getLength() != (byte) 2 || EmvTag.findTag((short) 0x9F4F) == null) {
            return;
        }

        short length = buildDataObjectListData((short) 0x9F4F, tmpBuffer, (short) 0);
        if (isTransactionEvent(TXN_LOGGED)) {
            transactionLog.replaceNewest(tmpBuffer, (short) 0, length);
        } else {
            transactionLog.append(tmpBuffer, (short) 0, length, logEntry.getData()[1]);
            setTransactionEvent(TXN_LOGGED);
        }
    }

    /**
     * READ RECORD of the transaction log SFI returns log records, other records as configured.
     */
    protected void processReadRecord(APDU apdu, byte[] buf) {
        EmvTag logEntry = EmvTag.findTag((short) 0x9F4D);
        if (logEntry != null && logEntry.getLength() == (byte) 2
            && buf[ISO7816.OFFSET_P2] == (byte) ((logEntry.getData()[0] << 3) | 0x04)) {
            short length = transactionLog.read(buf[ISO7816.OFFSET_P1], tmpBuffer, (short) 0);
            if (length < 0) {
                EmvApplet.logAndThrow(ISO7816.SW_RECORD_NOT_FOUND);
            }

            checkExpectedLength(buf, length);
            sendResponse(apdu, buf, tmpBuffer, (short) 0, length);
            return;
        }

        super.processReadRecord(apdu, buf);
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

        if (secondGenerateAc) {
            // Authorisation Response Code 'Y3' or 'Z3': terminal was unable to go online
            if (findTransactionData((short) 0x008A) && dataObjectListEntryLength == (short) 2) {
                short authorisationResponseCode = Util.getShort(foundTransactionData, foundTransactionDataOffset);
                if (authorisationResponseCode == ARC_UNABLE_TO_GO_ONLINE_APPROVED || authorisationResponseCode == ARC_UNABLE_TO_GO_ONLINE_DECLINED) {
                    setTransactionEvent(TXN_UNABLE_TO_GO_ONLINE);
                }
            }

            if (responseCryptogramType == CID_TC && isTransactionEvent(TXN_UNABLE_TO_GO_ONLINE)) {
                responseCryptogramType = cardRiskManagementUnableToGoOnline();
            }
        } else if (responseCryptogramType == CID_TC) {
            responseCryptogramType = cardRiskManagementOfflineRequest();
        }

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

        // CDA signature is not generated for AAC
        final boolean cdaPerformed = cdaRequested && responseCryptogramType != CID_AAC;
        if (cdaPerformed) {
            setTransactionEvent(TXN_CDA_PERFORMED);
        }
        transactionState[secondGenerateAc ? OFFSET_SECOND_CRYPTOGRAM_TYPE : OFFSET_FIRST_CRYPTOGRAM_TYPE] = responseCryptogramType;
        updateCardVerificationResults();

        if (isApplicationCryptogramMasterKeySet()) {
            if (secondGenerateAc) {
                generateApplicationCryptogram(cdol2Data, cdol2DataLength);
            } else {
                generateApplicationCryptogram(cdol1Data, cdol1DataLength);
            }
        }

        if (!secondGenerateAc) {
            storeFirstApplicationCryptogram();
        }

        completeGenerateAc(secondGenerateAc, responseCryptogramType);

        // Response of the first GENERATE AC can be recovered with RECOVER AC when DRDOL (tag 9F51) exists
        if (!secondGenerateAc && EmvTag.findTag((short) 0x9F51) != null) {
            recoverableDrdolDataLength = (short) 0;
            short length = buildDataObjectListData((short) 0x9F51, tmpBuffer, (short) 0);
            Util.arrayCopy(tmpBuffer, (short) 0, recoverableDrdolData, (short) 0, length);
            recoverableDrdolDataLength = length;
            captureRecoverableResponse = true;
        }

        if (cdaPerformed) {
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

    private void storeFirstApplicationCryptogram() {
        EmvTag applicationCryptogram = EmvTag.findTag((short) 0x9F26);
        if (applicationCryptogram != null && applicationCryptogram.getLength() == (byte) 8) {
            Util.arrayCopyNonAtomic(applicationCryptogram.getData(), (short) 0, firstApplicationCryptogram, (short) 0, (short) 8);
            // First script command MAC is chained from the Application Cryptogram
            Util.arrayCopyNonAtomic(applicationCryptogram.getData(), (short) 0, secureMessagingMacChain, (short) 0, (short) 8);
        }
    }

    /**
     * Update card risk management state and the transaction log after the Application Cryptogram is generated.
     */
    private void completeGenerateAc(boolean secondGenerateAc, byte responseCryptogramType) {
        if (!secondGenerateAc) {
            setRiskState(RISK_LAST_ONLINE_NOT_COMPLETED, responseCryptogramType == CID_ARQC);
            if (responseCryptogramType == CID_TC) {
                recordOfflineApproval();
            }
        } else {
            setRiskState(RISK_LAST_ONLINE_NOT_COMPLETED, false);
            if (isTransactionEvent(TXN_UNABLE_TO_GO_ONLINE)) {
                setRiskState(RISK_GO_ONLINE_NEXT, true);
                if (responseCryptogramType == CID_TC) {
                    recordOfflineApproval();
                }
            } else if (transactionState[OFFSET_ISSUER_AUTHENTICATION_FAILED] != (byte) 0x00) {
                setRiskState((byte) (RISK_GO_ONLINE_NEXT | RISK_ISSUER_AUTHENTICATION_FAILED), true);
            } else if (responseCryptogramType == CID_TC && isTransactionEvent(TXN_ISSUER_AUTHENTICATION_PERFORMED)) {
                recordOnlineApproval();
            }
        }

        if (responseCryptogramType == CID_AAC) {
            recordOfflineDataAuthenticationResult();
        }

        logTransaction();
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

        if (!received) {
            return;
        }

        setTransactionEvent(TXN_ISSUER_AUTHENTICATION_PERFORMED);
        if (!verifyIssuerAuthenticationData(cdol2Data, offset, length)) {
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
        final boolean relayResistancePerformed = transactionState[OFFSET_RELAY_RESISTANCE_PERFORMED] != (byte) 0x00;
        tmpBuffer[3] = (byte) (1 + dynamicNumberLength + 1 + 8 + 20);
        if (relayResistancePerformed) {
            tmpBuffer[3] += (byte) RELAY_RESISTANCE_DATA_LENGTH;
        }
        tmpBuffer[(short) (signedDataSize - 1)] = (byte) 0xBC;

        // ICC Dynamic Data: ICC Dynamic Number, Cryptogram Information Data, Application Cryptogram, Transaction Data Hash Code,
        // and relay resistance data when the Relay Resistance Protocol was performed (EMV Contactless Book C-2, Table 6.8)
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
        offset += shaMessageDigest.doFinal(buf, (short) 0, responseDataLength, tmpBuffer, offset);

        if (relayResistancePerformed) {
            Util.arrayCopyNonAtomic(relayResistanceData, (short) 0, tmpBuffer, offset, RELAY_RESISTANCE_DATA_LENGTH);
        }

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
        setTransactionEvent(TXN_ISSUER_AUTHENTICATION_PERFORMED);

        // Without Application Cryptogram Master Key, issuer authentication always succeeds
        if (isApplicationCryptogramMasterKeySet() && !verifyIssuerAuthenticationData(buf, ISO7816.OFFSET_CDATA, dataLength)) {
            transactionState[OFFSET_ISSUER_AUTHENTICATION_FAILED] = (byte) 0x01;
            EmvApplet.logAndThrow(SW_ISSUER_AUTHENTICATION_FAILED);
        }

        EmvApplet.logAndThrow(ISO7816.SW_NO_ERROR);
    }

    private void processGetData(APDU apdu, byte[] buf) {
        short tagId = Util.getShort(buf, ISO7816.OFFSET_P1);

        // EMV Book 3, 6.5.7 GET DATA: ATC, Last Online ATC Register, PIN Try Counter and Log Format,
        // Offline Accumulator Balance (EMV Contactless Book C-2) and tags writable with PUT DATA
        switch (tagId) {
            case (short) 0x9F36:
            case (short) 0x9F13:
            case (short) 0x9F17:
            case (short) 0x9F4F:
            case (short) 0x9F50:
                break;
            default:
                if (!isPutDataTag(tagId)) {
                    EmvApplet.logAndThrow(SW_REFERENCED_DATA_NOT_FOUND);
                }
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

        Util.arrayFillNonAtomic(transactionState, (short) 0, TRANSACTION_STATE_LENGTH, (byte) 0x00);
        transactionState[OFFSET_PREVIOUS_RISK_STATE] = riskState;
        transactionState[OFFSET_PREVIOUS_SCRIPT_COMMAND_COUNT] = lastScriptCommandCount;

        if (cryptogramInGetProcessingOptions) {
            generateGetProcessingOptionsCryptogram(buf);
            sendResponseTemplate(apdu, buf, responseTemplateGetProcessingOptions);
            transactionState[OFFSET_STATE] = STATE_COMPLETED;
            return;
        }

        sendResponseTemplate(apdu, buf, responseTemplateGetProcessingOptions);

        transactionState[OFFSET_STATE] = STATE_GPO_DONE;
    }

    /**
     * qVSDC: the card completes the transaction in GET PROCESSING OPTIONS (EMV Contactless Book C-3). The card decides the cryptogram type
     * from Terminal Transaction Qualifiers (9F66): byte 2 bit 8 online cryptogram required, byte 1 bit 4 offline-only reader.
     * Application Cryptogram is generated over the PDOL related data arranged as CDOL1 related data when CDOL1 exists.
     * With DDA supported in AIP, fDDA Signed Dynamic Application Data (9F4B) and Card Authentication Related Data (9F69) are generated.
     */
    private void generateGetProcessingOptionsCryptogram(byte[] buf) {
        boolean onlineCryptogramRequired = true;
        boolean offlineOnlyReader = false;
        if (findTransactionData((short) 0x9F66) && dataObjectListEntryLength >= (short) 2) {
            offlineOnlyReader = (foundTransactionData[foundTransactionDataOffset] & (byte) 0x08) != 0;
            onlineCryptogramRequired = (foundTransactionData[(short) (foundTransactionDataOffset + 1)] & (byte) 0x80) != 0;
        }

        byte cryptogramType = CID_ARQC;
        if (!onlineCryptogramRequired && (cardRiskManagement || offlineOnlyReader)) {
            cryptogramType = cardRiskManagementOfflineRequest();
            // Offline-only reader cannot go online, the card approves or declines by the upper limits
            if (cryptogramType == CID_ARQC && offlineOnlyReader) {
                setTransactionEvent(TXN_UNABLE_TO_GO_ONLINE);
                cryptogramType = cardRiskManagementUnableToGoOnline();
            }
        }

        if (applicationBlocked) {
            cryptogramType = CID_AAC;
        }

        tmpBuffer[0] = cryptogramType;
        EmvTag.setTag((short) 0x9F27, tmpBuffer, (short) 0, (byte) 1);
        transactionState[OFFSET_FIRST_CRYPTOGRAM_TYPE] = cryptogramType;

        if (EmvTag.findTag((short) 0x008C) != null) {
            short length = buildDataObjectListData((short) 0x008C, cdol1Data, (short) 0);
            cdol1DataLength = length;
        }

        if (isFastDynamicDataAuthenticationSupported()) {
            setTransactionEvent(TXN_DDA_PERFORMED);
        }
        updateCardVerificationResults();

        if (isApplicationCryptogramMasterKeySet()) {
            if (cdol1DataLength > (short) 0) {
                generateApplicationCryptogram(cdol1Data, cdol1DataLength);
            } else {
                generateApplicationCryptogram(pdolData, pdolDataLength);
            }
        }
        storeFirstApplicationCryptogram();

        if (isFastDynamicDataAuthenticationSupported()) {
            generateFastDynamicDataAuthentication(buf);
        }

        if (cryptogramType == CID_TC) {
            recordOfflineApproval();
            if (isTransactionEvent(TXN_UNABLE_TO_GO_ONLINE)) {
                setRiskState(RISK_GO_ONLINE_NEXT, true);
            }
        }

        logTransaction();
    }

    private boolean isFastDynamicDataAuthenticationSupported() {
        // AIP byte 1 bit 6: DDA supported
        EmvTag applicationInterchangeProfile = EmvTag.findTag((short) 0x0082);
        return applicationInterchangeProfile != null && applicationInterchangeProfile.getLength() == (byte) 2
            && (applicationInterchangeProfile.getData()[0] & (byte) 0x20) != 0
            && rsaPrivateKey != null && rsaPrivateKey.isInitialized();
    }

    /**
     * fDDA version '01': Card Authentication Related Data (9F69) := '01' || Card Unpredictable Number (4) || CTQ (2), and
     * Signed Dynamic Application Data (9F4B) over terminal dynamic data
     * Unpredictable Number (9F37) || Amount, Authorised (9F02) || Transaction Currency Code (5F2A) || Card Authentication Related Data.
     */
    private void generateFastDynamicDataAuthentication(byte[] buf) {
        tmpBuffer[0] = (byte) 0x01;
        randomData.generateData(tmpBuffer, (short) 1, (short) 4);
        if (!useRandom) {
            Util.arrayFillNonAtomic(tmpBuffer, (short) 1, (short) 4, (byte) 0xAB);
        }
        Util.arrayFillNonAtomic(tmpBuffer, (short) 5, (short) 2, (byte) 0x00);
        EmvTag cardTransactionQualifiers = EmvTag.findTag((short) 0x9F6C);
        if (cardTransactionQualifiers != null && cardTransactionQualifiers.getLength() == (byte) 2) {
            Util.arrayCopyNonAtomic(cardTransactionQualifiers.getData(), (short) 0, tmpBuffer, (short) 5, (short) 2);
        }
        final EmvTag cardAuthenticationRelatedData = EmvTag.setTag((short) 0x9F69, tmpBuffer, (short) 0, (byte) 7);

        short length = (short) 0;
        length = appendTransactionData((short) 0x9F37, buf, length);
        length = appendTransactionData((short) 0x9F02, buf, length);
        length = appendTransactionData((short) 0x5F2A, buf, length);
        length = Util.arrayCopyNonAtomic(cardAuthenticationRelatedData.getData(), (short) 0, buf, length, (short) 7);

        generateSignedDynamicApplicationData(buf, (short) 0, length, buf);
    }

    private short appendTransactionData(short tagId, byte[] dst, short dstOffset) {
        if (!findTransactionData(tagId)) {
            return dstOffset;
        }
        return Util.arrayCopyNonAtomic(foundTransactionData, foundTransactionDataOffset, dst, dstOffset, dataObjectListEntryLength);
    }

    private boolean isRelayResistanceProtocolSupported() {
        // AIP byte 2 bit 1: Relay resistance protocol is supported (EMV Contactless Book C-2, A.1.16)
        EmvTag applicationInterchangeProfile = EmvTag.findTag((short) 0x0082);
        return applicationInterchangeProfile != null && applicationInterchangeProfile.getLength() == (byte) 2
            && (applicationInterchangeProfile.getData()[1] & (byte) 0x01) != 0;
    }

    /**
     * EXCHANGE RELAY RESISTANCE DATA (EMV Contactless Book C-2, 5.3). The terminal times this command, and may repeat it
     * with a new Terminal Relay Resistance Entropy. Response is format 1:
     * '80' '0A' Device Relay Resistance Entropy (4) || Min Time (2) || Max Time (2) || Device Estimated Transmission Time (2)
     */
    private void processExchangeRelayResistanceData(APDU apdu, byte[] buf, short dataLength) {
        if (!isRelayResistanceProtocolSupported()) {
            commandNotSupported(CMD_EXCHANGE_RELAY_RESISTANCE_DATA);
        }

        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x0000) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        if (dataLength != RELAY_RESISTANCE_ENTROPY_LENGTH) {
            EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
        }

        // Between GET PROCESSING OPTIONS and the first GENERATE AC
        if (transactionState[OFFSET_STATE] != STATE_GPO_DONE) {
            EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Terminal Relay Resistance Entropy
        Util.arrayCopyNonAtomic(buf, (short) ISO7816.OFFSET_CDATA, relayResistanceData, (short) 0, RELAY_RESISTANCE_ENTROPY_LENGTH);

        // Device Relay Resistance Entropy, fresh for each exchange
        randomData.generateData(relayResistanceData, RELAY_RESISTANCE_ENTROPY_LENGTH, RELAY_RESISTANCE_ENTROPY_LENGTH);
        if (!useRandom) {
            Util.arrayFillNonAtomic(relayResistanceData, RELAY_RESISTANCE_ENTROPY_LENGTH, RELAY_RESISTANCE_ENTROPY_LENGTH, (byte) 0xAB);
        }

        Util.arrayCopyNonAtomic(relayResistanceTiming, (short) 0,
            relayResistanceData, (short) (2 * RELAY_RESISTANCE_ENTROPY_LENGTH), RELAY_RESISTANCE_TIMING_LENGTH);

        transactionState[OFFSET_RELAY_RESISTANCE_PERFORMED] = (byte) 0x01;

        short responseLength = (short) (RELAY_RESISTANCE_DATA_LENGTH - RELAY_RESISTANCE_ENTROPY_LENGTH);
        tmpBuffer[0] = (byte) 0x80;
        tmpBuffer[1] = (byte) responseLength;
        Util.arrayCopyNonAtomic(relayResistanceData, RELAY_RESISTANCE_ENTROPY_LENGTH, tmpBuffer, (short) 2, responseLength);

        sendResponse(apdu, buf, tmpBuffer, (short) 0, (short) (2 + responseLength));
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

        generateSignedDynamicApplicationData(buf, (short) ISO7816.OFFSET_CDATA, dataLength, buf);
        setTransactionEvent(TXN_DDA_PERFORMED);

        sendResponseTemplate(apdu, buf, responseTemplateDda);
    }

    /**
     * Signed Dynamic Application Data (tag 9F4B) of DDA and fDDA over terminal dynamic data (EMV Book 2, 6.5.1).
     * Signature is written to dst, terminal dynamic data may be in the same array.
     */
    private void generateSignedDynamicApplicationData(byte[] terminalData, short terminalDataOffset, short terminalDataLength, byte[] dst) {
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
        shaMessageDigest.doFinal(terminalData, terminalDataOffset, terminalDataLength, tmpBuffer, checksumStartIndex);

        signWithIccPrivateKey(dst);

        EmvTag.setTag((short) 0x9F4B, dst, (short) 0, (byte) signedDataSize);
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

        setTransactionEvent(TXN_OFFLINE_PIN_PERFORMED);

        byte[] givenPinBlock = buf;
        short givenPinBlockOffset = (short) ISO7816.OFFSET_CDATA;

        if (pinTypeQualifier == (byte) 0x80) {
            // Plaintext PIN block
            if (dataLength != (short) 8) {
                EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
            }
        } else {
            // Enciphered PIN block, EMV Book 2, 7.2 PIN Encipherment and Verification.
            // ICC PIN Encipherment Private Key is used when set, otherwise ICC Private Key (EMV Book 2, 7.1)
            RSAPrivateKey pinKey = pinRsaPrivateKey;
            short pinKeyByteSize = pinRsaPrivateKeyByteSize;
            if (pinKey == null || !pinKey.isInitialized()) {
                requireRsaPrivateKey();
                pinKey = rsaPrivateKey;
                pinKeyByteSize = rsaPrivateKeyByteSize;
            }

            if (dataLength != pinKeyByteSize) {
                EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
            }

            if (!challengeValid[0]) {
                EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            // ICC Unpredictable Number is valid for one verification only
            challengeValid[0] = false;

            rsaCipher.init(pinKey, Cipher.MODE_DECRYPT);
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
            setTransactionEvent(TXN_OFFLINE_PIN_FAILED);
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
    private void verifySecureMessagingFormat1(byte[] buf, short dataLength) {
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
     * Verify secure messaging format 2 command data field: plaintext or enciphered data without TLV coding followed by an 8-byte MAC
     * (EMV Book 2, 9.2.1.2), the format of the payment system issuer scripts with CLA '84'. MAC is computed with the MAC Session Key
     * derived from MK_SMI and the Application Cryptogram of the first GENERATE AC over
     * CLA INS P1 P2 Lc || ATC || Application Cryptogram || data || padding.
     */
    private void verifySecureMessagingFormat2(byte[] buf, short dataLength) {
        if (dataLength < SECURE_MESSAGING_FORMAT_2_MAC_LENGTH) {
            EmvApplet.logAndThrow(SW_EXPECTED_SM_DATA_OBJECTS_MISSING);
        }

        EmvTag applicationTransactionCounter = EmvTag.findTag((short) 0x9F36);
        if (applicationTransactionCounter == null || applicationTransactionCounter.getLength() != (byte) 2) {
            EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        final short plainDataLength = (short) (dataLength - SECURE_MESSAGING_FORMAT_2_MAC_LENGTH);

        deriveSessionKey(secureMessagingMacMasterKey, firstApplicationCryptogram, (short) 8);

        macInit();
        macUpdate(buf, (short) ISO7816.OFFSET_CLA, (short) 5);
        macUpdate(applicationTransactionCounter.getData(), (short) 0, (short) 2);
        macUpdate(firstApplicationCryptogram, (short) 0, (short) 8);
        macUpdate(buf, (short) ISO7816.OFFSET_CDATA, plainDataLength);
        macFinal(tmpBuffer, (short) 0);

        if (Util.arrayCompare(tmpBuffer, (short) 0, buf, (short) (ISO7816.OFFSET_CDATA + plainDataLength),
            SECURE_MESSAGING_FORMAT_2_MAC_LENGTH) != (byte) 0x00) {
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

        // Script results of the latest transaction with scripts are reported in the CVR
        if (!isTransactionEvent(TXN_SCRIPT_RECEIVED)) {
            setTransactionEvent(TXN_SCRIPT_RECEIVED);
            lastScriptCommandCount = (byte) 0;
            setRiskState(RISK_SCRIPT_FAILED, false);
        }
        if (lastScriptCommandCount < (byte) 15) {
            lastScriptCommandCount++;
        }

        try {
            executeScriptCommand(buf, cmd, dataLength);
        } catch (ISOException e) {
            setRiskState(RISK_SCRIPT_FAILED, true);
            throw e;
        }

        EmvApplet.logAndThrow(ISO7816.SW_NO_ERROR);
    }

    private void executeScriptCommand(byte[] buf, short cmd, short dataLength) {
        if (isSecureMessagingFormat2(buf)) {
            verifySecureMessagingFormat2(buf, dataLength);
        } else {
            verifySecureMessagingFormat1(buf, dataLength);
        }

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
    }

    /**
     * True if tag is in the PUT DATA tag list.
     */
    private boolean isPutDataTag(short tagId) {
        byte[] tags = putDataTags.getData();
        short length = (short) (putDataTags.getLength() & 0x00FF);
        for (short i = (short) 0; i < length; i += EmvTag.tagEntryLength(tags, i)) {
            if (EmvTag.tagEntryLength(tags, i) == (short) 2 && Util.getShort(tags, i) == tagId) {
                return true;
            }
            if (EmvTag.tagEntryLength(tags, i) == (short) 1 && (short) (tags[i] & 0x00FF) == tagId) {
                return true;
            }
        }
        return false;
    }

    /**
     * PUT DATA without secure messaging (EMV Contactless Book C-2, 5.5), e.g. Data Storage or Offline Accumulator Balance.
     * Only tags configured as writable are accepted.
     */
    private void processPutData(APDU apdu, byte[] buf, short dataLength) {
        if (putDataTags.getLength() == (byte) 0) {
            commandNotSupported(CMD_PUT_DATA_PLAIN);
        }

        if (transactionState[OFFSET_STATE] == STATE_IDLE) {
            EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short tagId = Util.getShort(buf, ISO7816.OFFSET_P1);
        if (!isPutDataTag(tagId)) {
            EmvApplet.logAndThrow(SW_REFERENCED_DATA_NOT_FOUND);
        }

        EmvTag.setTag(tagId, buf, (short) ISO7816.OFFSET_CDATA, (byte) dataLength);

        EmvApplet.logAndThrow(ISO7816.SW_NO_ERROR);
    }

    /**
     * COMPUTE CRYPTOGRAPHIC CHECKSUM for mag-stripe mode (EMV Contactless Book C-2, 5.2).
     * Command data is UDOL (tag 9F69) related data, default UDOL is Unpredictable Number (Numeric) '9F6A 04'.
     * CVC3 := two rightmost bytes of DES3(KD_CVC3)[IVCVC3 (2) || Unpredictable Number (Numeric) (4) || ATC (2)],
     * for both Track 1 (tag 9F60) and Track 2 (tag 9F61).
     */
    private void processComputeCryptographicChecksum(APDU apdu, byte[] buf, short dataLength) {
        if (!isKeySet(cvc3Key)) {
            commandNotSupported(CMD_COMPUTE_CRYPTOGRAPHIC_CHECKSUM);
        }

        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x8E80) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        if (transactionState[OFFSET_STATE] != STATE_GPO_DONE) {
            EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short unpredictableNumberOffset = (short) ISO7816.OFFSET_CDATA;
        short expectedLength = findDataObjectListEntry((short) 0x9F69, (short) 0);
        if (expectedLength < 0) {
            expectedLength = (short) 4;
        } else {
            short offset = findDataObjectListEntry((short) 0x9F69, (short) 0x9F6A);
            if (offset < 0 || dataObjectListEntryLength != (short) 4) {
                EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            unpredictableNumberOffset += offset;
        }
        if (dataLength != expectedLength) {
            EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
        }

        EmvTag applicationTransactionCounter = EmvTag.findTag((short) 0x9F36);
        if (applicationTransactionCounter == null || applicationTransactionCounter.getLength() != (byte) 2) {
            EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Unpredictable Number is logged like PDOL related data
        pdolDataLength = (short) 0;

        desCipher.init(cvc3Key, Cipher.MODE_ENCRYPT);
        for (short track = (short) 0; track < (short) 2; track++) {
            Util.arrayCopyNonAtomic(cvc3InitializationVectors, (short) (track * 2), tmpBuffer, (short) 0, (short) 2);
            Util.arrayCopyNonAtomic(buf, unpredictableNumberOffset, tmpBuffer, (short) 2, (short) 4);
            Util.arrayCopyNonAtomic(applicationTransactionCounter.getData(), (short) 0, tmpBuffer, (short) 6, (short) 2);
            desCipher.doFinal(tmpBuffer, (short) 0, (short) 8, tmpBuffer, (short) 0);
            EmvTag.setTag(track == (short) 0 ? (short) 0x9F60 : (short) 0x9F61, tmpBuffer, (short) 6, (byte) 2);
        }

        logTransaction();

        sendResponseTemplate(apdu, buf, responseTemplateComputeCryptographicChecksum, (short) 0x0077);

        transactionState[OFFSET_STATE] = STATE_COMPLETED;
    }

    /**
     * RECOVER AC (EMV Contactless Book C-2, 5.6): after a torn first GENERATE AC, the terminal sends DRDOL (tag 9F51) related data
     * of the torn transaction in a new transaction. The card returns the response of the torn GENERATE AC if the data matches.
     */
    private void processRecoverAc(APDU apdu, byte[] buf, short dataLength) {
        short expectedLength = findDataObjectListEntry((short) 0x9F51, (short) 0);
        if (expectedLength < 0) {
            commandNotSupported(CMD_RECOVER_AC);
        }

        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x0000) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        if (transactionState[OFFSET_STATE] != STATE_GPO_DONE) {
            EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        if (dataLength != expectedLength) {
            EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
        }

        if (recoverableResponseLength == (short) 0 || recoverableDrdolDataLength != dataLength
            || Util.arrayCompare(buf, (short) ISO7816.OFFSET_CDATA, recoverableDrdolData, (short) 0, dataLength) != (byte) 0x00) {
            EmvApplet.logAndThrow(SW_REFERENCED_DATA_NOT_FOUND);
        }

        transactionState[OFFSET_STATE] = STATE_COMPLETED;

        sendResponse(apdu, buf, recoverableResponse, (short) 0, recoverableResponseLength);
    }

    /**
     * Keep a copy of the first GENERATE AC response for RECOVER AC.
     */
    protected void sendResponse(APDU apdu, byte[] buf, byte[] data, short dataOffset, short length) {
        if (captureRecoverableResponse) {
            captureRecoverableResponse = false;
            recoverableResponseLength = (short) 0;
            // Response data in the APDU buffer is at the command data offset
            short offset = (data == buf) ? (short) ISO7816.OFFSET_CDATA : dataOffset;
            Util.arrayCopy(data, offset, recoverableResponse, (short) 0, length);
            recoverableResponseLength = length;
        }

        super.sendResponse(apdu, buf, data, dataOffset, length);
    }

    protected TagTemplate getTagTemplate(short templateId) {
        if (templateId == (short) 0x0007) {
            return responseTemplateComputeCryptographicChecksum;
        }
        return null;
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
            case CMD_EXCHANGE_RELAY_RESISTANCE_DATA:
                processExchangeRelayResistanceData(apdu, buf, dataLength);
                break;
            case CMD_COMPUTE_CRYPTOGRAPHIC_CHECKSUM:
                processComputeCryptographicChecksum(apdu, buf, dataLength);
                break;
            case CMD_RECOVER_AC:
                processRecoverAc(apdu, buf, dataLength);
                break;
            case CMD_PUT_DATA_PLAIN:
                processPutData(apdu, buf, dataLength);
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
