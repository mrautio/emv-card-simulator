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

public abstract class EmvApplet extends Applet {
    /*// for dev "debugging"
    static void printAsHex(String type, byte[] buf) {
        printAsHex(type, buf, 0, buf.length);
    }

    static void printAsHex(String type, byte[] buf, int offset, int length) {
        System.out.println(String.format("%s [%02X] %s", type, length, toHexString(buf, offset, length)));
    }

    static String toHexString(byte[] buf, int offset, int length) {
        String result = "[";
        for (int i = offset; i < offset + length - 1; i++) {
            result += String.format("%02X, ", buf[i]);
        }
        result += String.format("%02X]", buf[offset + length - 1]);

        return result;
    }

    static void printEmvTags() {
        for (EmvTag iter = EmvTag.getHead(); iter != null; iter = iter.getNext()) {
            printAsHex(toHexString(iter.getTag(), 0, 2), iter.getData(), 0, (iter.getLength() & 0x00FF));
        }
    }
    */

    protected static final short CMD_SET_SETTINGS              = (short) 0x8000;
    protected static final short CMD_SET_EMV_TAG               = (short) 0x8001;
    protected static final short CMD_SET_EMV_TAG_FUZZ          = (short) 0x8011;
    protected static final short CMD_SET_TAG_TEMPLATE          = (short) 0x8002;
    protected static final short CMD_SET_READ_RECORD_TEMPLATE  = (short) 0x8003;
    protected static final short CMD_SET_READ_RECORD_DATA      = (short) 0x8004;
    protected static final short CMD_FACTORY_RESET             = (short) 0x8005;
    protected static final short CMD_LOG_CONSUME               = (short) 0x8006;
    protected static final short CMD_FUZZ_RESET                = (short) 0x8007;
    protected static final short CMD_SELECT = (short) 0x00A4;
    protected static final short CMD_READ_RECORD = (short) 0x00B2;
    protected static final short CMD_GET_RESPONSE = (short) 0x00C0;
    protected static final short CMD_DDA = (short) 0x0088;
    protected static final short CMD_VERIFY_PIN = (short) 0x0020;
    protected static final short CMD_GET_CHALLENGE = (short) 0x0084;
    protected static final short CMD_GET_DATA = (short) 0x80CA;
    protected static final short CMD_GET_PROCESSING_OPTIONS = (short) 0x80A8;
    protected static final short CMD_GENERATE_AC = (short) 0x80AE;
    protected static final short CMD_EXTERNAL_AUTHENTICATE = (short) 0x0082;
    // Relay Resistance Protocol (EMV Contactless Book C-2, 5.3)
    protected static final short CMD_EXCHANGE_RELAY_RESISTANCE_DATA = (short) 0x80EA;
    // Mag-stripe mode, torn transaction recovery and Data Storage (EMV Contactless Book C-2, 5)
    protected static final short CMD_COMPUTE_CRYPTOGRAPHIC_CHECKSUM = (short) 0x802A;
    protected static final short CMD_RECOVER_AC = (short) 0x80D0;
    protected static final short CMD_PUT_DATA_PLAIN = (short) 0x80DA;
    // Post-issuance commands with secure messaging (EMV Book 3, 6.5), format 1 (CLA '8C') or format 2 (CLA '84')
    protected static final short CMD_APPLICATION_BLOCK = (short) 0x8C1E;
    protected static final short CMD_APPLICATION_UNBLOCK = (short) 0x8C18;
    protected static final short CMD_CARD_BLOCK = (short) 0x8C16;
    protected static final short CMD_PIN_CHANGE_UNBLOCK = (short) 0x8C24;
    // Payment system specific issuer script commands
    protected static final short CMD_PUT_DATA = (short) 0x0CDA;
    protected static final short CMD_PUT_DATA_PROPRIETARY = (short) 0x8CDA;
    protected static final short CMD_UPDATE_RECORD = (short) 0x0CDC;
    protected static final short CMD_UPDATE_RECORD_PROPRIETARY = (short) 0x8CDC;

    protected static final short SW_AUTHENTICATION_METHOD_BLOCKED = (short) 0x6983;
    protected static final short SW_REFERENCED_DATA_NOT_FOUND = (short) 0x6A88;
    protected static final short SW_ISSUER_AUTHENTICATION_FAILED = (short) 0x6300;
    protected static final short SW_SELECTED_FILE_INVALIDATED = (short) 0x6283;
    protected static final short SW_EXPECTED_SM_DATA_OBJECTS_MISSING = (short) 0x6987;
    protected static final short SW_INCORRECT_SM_DATA_OBJECTS = (short) 0x6988;

    // CARD BLOCK disables all applications (EMV Book 3, 6.5.3), cleared by factory reset
    protected static boolean cardBlocked = false;

    public static RandomData randomData;
    public static byte[] tmpBuffer;

    // Response data longer than MAX_RESPONSE_PART_LENGTH is sent in parts: the card returns a part with '61xx' and
    // the terminal gets the rest with GET RESPONSE (ISO/IEC 7816-4, 5.3.4), e.g. responses with a 1984 bit ICC key signature.
    // Part length fits SW2 of '61xx' and the one byte length of ApduLog entries.
    protected static final short MAX_RESPONSE_PART_LENGTH = (short) 255;
    protected static final short RESPONSE_BUFFER_SIZE = (short) 512;
    // Template tag and a three byte length, e.g. '77 82 01 4C'
    private static final short RESPONSE_TEMPLATE_HEADER_LENGTH = (short) 4;
    private static final short PENDING_RESPONSE_OFFSET = (short) 0;
    private static final short PENDING_RESPONSE_LENGTH = (short) 1;

    // Shared by the applets of the package like tmpBuffer, only one of them is selected at a time
    protected static byte[] responseBuffer;
    // Offset and remaining length of the response data in responseBuffer not yet sent
    private short[] pendingResponse;
    // Response data of a case 4 command with T=0 is sent only with GET RESPONSE
    private boolean[] responseDeferred;

    protected static void logAndThrow(short responseTrailer) {
        ApduLog.addLogEntry(responseTrailer);
        ISOException.throwIt(responseTrailer);
    }

    /**
     * Reject a command the application does not support, 6882 if it uses secure messaging.
     */
    protected static void commandNotSupported(short cmd) {
        if ((cmd & (short) 0x0C00) != 0) {
            logAndThrow(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
        }
        logAndThrow(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    // EMV tags and records of this applet instance
    protected DataStore dataStore;

    protected TagTemplate responseTemplateGetProcessingOptions;
    // GET PROCESSING OPTIONS response of the contactless interface, responseTemplateGetProcessingOptions is used when not set
    protected TagTemplate responseTemplateGetProcessingOptionsContactless;
    protected TagTemplate responseTemplateDda;
    protected TagTemplate responseTemplateGenerateAc;
    protected TagTemplate tag6fFci;
    protected TagTemplate tagA5Fci;
    protected TagTemplate tagBf0cFci;

    protected byte[] defaultReadRecord;

    // Length of the data object found by the latest findDataObjectListEntry tag search
    protected static short dataObjectListEntryLength = 0;


    protected short responseTemplateTag;

    private static final byte[] DEFAULT_FCI_TEMPLATE = { (byte) 0x00, (byte) 0x84, (byte) 0x00, (byte) 0xA5 };
    protected boolean randomResponseSuffixData;

    /**
     * Process simulator setup commands. Returns true if the command was a setup command.
     */
    protected boolean processSetupCommand(APDU apdu, byte[] buf, short cmd) {
        switch (cmd) {
            case CMD_SET_SETTINGS:
                processSetSettings(apdu, buf, receiveData(apdu, buf));
                return true;
            case CMD_SET_EMV_TAG:
                processSetEmvTag(apdu, buf, receiveData(apdu, buf));
                return true;
            case CMD_SET_EMV_TAG_FUZZ:
                processSetEmvTagFuzz(apdu, buf, receiveData(apdu, buf));
                return true;
            case CMD_SET_TAG_TEMPLATE:
                processSetTagTemplate(apdu, buf, receiveData(apdu, buf));
                return true;
            case CMD_SET_READ_RECORD_TEMPLATE:
                processSetReadRecordTemplate(apdu, buf, receiveData(apdu, buf));
                return true;
            case CMD_SET_READ_RECORD_DATA:
                processSetReadRecordData(apdu, buf, receiveData(apdu, buf));
                return true;
            case CMD_FACTORY_RESET:
                factoryReset(apdu, buf);
                return true;
            case CMD_FUZZ_RESET:
                fuzzReset(apdu, buf);
                return true;
            case CMD_LOG_CONSUME:
                consumeLogs(apdu, buf);
                return true;
            default:
                return false;
        }
    }

    /**
     * True if the command is a simulator setup command, i.e. not an EMV command.
     */
    public static boolean isSetupCommand(short cmd) {
        switch (cmd) {
            case CMD_SET_SETTINGS:
            case CMD_SET_EMV_TAG:
            case CMD_SET_EMV_TAG_FUZZ:
            case CMD_SET_TAG_TEMPLATE:
            case CMD_SET_READ_RECORD_TEMPLATE:
            case CMD_SET_READ_RECORD_DATA:
            case CMD_FACTORY_RESET:
            case CMD_FUZZ_RESET:
            case CMD_LOG_CONSUME:
                return true;
            default:
                return false;
        }
    }

    protected abstract void processSetSettings(APDU apdu, byte[] buf, short dataLength);

    protected abstract void processSelect(APDU apdu, byte[] buf);

    /**
     * Process EMV commands other than SELECT. Throws SW_INS_NOT_SUPPORTED for unknown commands.
     */
    protected abstract void processCommand(APDU apdu, byte[] buf, short cmd, short dataLength);

    /**
     * True if the command has a command data field (ISO 7816-4 case 3 or 4).
     */
    protected boolean hasCommandData(short cmd) {
        switch (cmd) {
            case CMD_SELECT:
            case CMD_DDA:
            case CMD_VERIFY_PIN:
            case CMD_GET_PROCESSING_OPTIONS:
            case CMD_GENERATE_AC:
            case CMD_EXTERNAL_AUTHENTICATE:
            case CMD_EXCHANGE_RELAY_RESISTANCE_DATA:
            case CMD_COMPUTE_CRYPTOGRAPHIC_CHECKSUM:
            case CMD_RECOVER_AC:
            case CMD_PUT_DATA_PLAIN:
            case CMD_APPLICATION_BLOCK:
            case CMD_APPLICATION_UNBLOCK:
            case CMD_CARD_BLOCK:
            case CMD_PIN_CHANGE_UNBLOCK:
            case CMD_PUT_DATA:
            case CMD_PUT_DATA_PROPRIETARY:
            case CMD_UPDATE_RECORD:
            case CMD_UPDATE_RECORD_PROPRIETARY:
                return true;
            default:
                return false;
        }
    }

    /**
     * Validate CLA and return CLA || INS with the logical channel bits cleared.
     * Secure messaging bits are set for both secure messaging format 1 (CLA 'xC') and format 2 (CLA 'x4'), EMV Book 2, 9.2.1,
     * the format is given by isSecureMessagingFormat2.
     */
    protected static short getCommand(byte[] buf) {
        byte cla = buf[ISO7816.OFFSET_CLA];

        // Only the first interindustry class (000x xxxx) and its proprietary counterpart (100x xxxx) are supported
        if ((cla & (byte) 0x60) != 0) {
            ApduLog.addCommandLogEntry(buf, (short) 0, ISO7816.OFFSET_CDATA);
            EmvApplet.logAndThrow(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // Secure messaging indication bits, ISO/IEC 7816-4 secure messaging without header authentication (CLA 'x8') is not used by EMV
        byte secureMessaging = (byte) (cla & (byte) 0x0C);
        if (secureMessaging == (byte) 0x08) {
            ApduLog.addCommandLogEntry(buf, (short) 0, ISO7816.OFFSET_CDATA);
            EmvApplet.logAndThrow(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
        }
        if (secureMessaging != 0) {
            cla |= (byte) 0x0C;
        }

        return Util.makeShort((byte) (cla & (byte) 0x8C), buf[ISO7816.OFFSET_INS]);
    }

    /**
     * True if the command uses secure messaging format 2 (CLA 'x4'), payment system specific format of EMV Book 2, 9.2.1.2.
     */
    protected static boolean isSecureMessagingFormat2(byte[] buf) {
        return (byte) (buf[ISO7816.OFFSET_CLA] & (byte) 0x0C) == (byte) 0x04;
    }

    /**
     * Receive the whole command data field to the APDU buffer and return its length.
     */
    protected static short receiveData(APDU apdu, byte[] buf) {
        short dataLength = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);

        // JCRE may already have received the data, e.g. for applet SELECT
        if (apdu.getCurrentState() != APDU.STATE_INITIAL) {
            return dataLength;
        }

        short received = apdu.setIncomingAndReceive();
        while (received < dataLength) {
            short count = apdu.receiveBytes((short) (ISO7816.OFFSET_CDATA + received));
            if (count == 0) {
                break;
            }
            received += count;
        }

        if (received != dataLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        return dataLength;
    }

    /**
     * True for the T=0 protocol of the contact interface (ISO/IEC 7816-3). T=0 cannot send response data with a case 4
     * command, the card returns '61xx' and the terminal gets the data with GET RESPONSE. P3 of a case 2 command is the
     * exact response length, another length is answered with '6Cxx' (EMV Book 1, 9.3.1 and Annex A).
     * T=1 and the contactless interface (ISO/IEC 14443-4) send the response data with the command.
     */
    protected static boolean isProtocolT0() {
        byte protocol = APDU.getProtocol();
        return (byte) (protocol & APDU.PROTOCOL_MEDIA_MASK) == APDU.PROTOCOL_MEDIA_DEFAULT
            && (byte) (protocol & APDU.PROTOCOL_TYPE_MASK) == APDU.PROTOCOL_T0;
    }

    /**
     * True for the contactless interface (ISO/IEC 14443 type A or B).
     */
    protected static boolean isContactlessInterface() {
        byte media = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
        return media == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A || media == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B;
    }

    /**
     * Check Le of a case 2 command against the response length. Le 0x00 accepts any response length,
     * except with T=0 where P3 0x00 is 256 bytes.
     */
    protected static void checkExpectedLength(byte[] buf, short responseLength) {
        short expectedLength = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
        if (expectedLength == 0 && isProtocolT0()) {
            expectedLength = (short) 256;
        }
        if (expectedLength != 0 && expectedLength != responseLength) {
            EmvApplet.logAndThrow((short) (ISO7816.SW_CORRECT_LENGTH_00 | (responseLength & 0x00FF)));
        }
    }

    /**
     * Find a tag from data object list (DOL) stored in EmvTag dolTagId.
     * Returns the offset of the tag value in DOL related data, or -1 if not found.
     * When searchTagId is 0, returns the total length of DOL related data, or -1 if the DOL does not exist.
     * When the tag is found, its length is stored to dataObjectListEntryLength.
     */
    protected static short findDataObjectListEntry(short dolTagId, short searchTagId) {
        EmvTag dol = EmvTag.findTag(dolTagId);
        if (dol == null) {
            return (short) -1;
        }

        byte[] dolData = dol.getData();
        short dolLength = (short) (dol.getLength() & 0x00FF);
        short valueOffset = (short) 0;

        short i = (short) 0;
        while (i < dolLength) {
            short tagId = (short) (dolData[i] & 0x00FF);
            if ((dolData[i] & (byte) 0x1F) == (byte) 0x1F) {
                // Multi-byte tag, only two first bytes are used for identification
                i++;
                tagId = Util.makeShort((byte) tagId, dolData[i]);
                while (i < dolLength && (dolData[i] & (byte) 0x80) != 0) {
                    i++;
                }
            }
            i++;

            if (i >= dolLength) {
                break;
            }

            short valueLength = (short) (dolData[i] & 0x00FF);
            i++;

            if (searchTagId != 0 && tagId == searchTagId) {
                dataObjectListEntryLength = valueLength;
                return valueOffset;
            }

            valueOffset += valueLength;
        }

        return (searchTagId == 0) ? valueOffset : (short) -1;
    }

    /**
     * Process APDU command.
     */
    public void process(APDU apdu) {
        DataStore.current = dataStore;
        EmvTag.contactless = isContactlessInterface();

        byte[] buf = apdu.getBuffer();

        short cmd = getCommand(buf);

        // Response data not retrieved with GET RESPONSE is discarded by the next command
        if (cmd != CMD_GET_RESPONSE) {
            pendingResponse[PENDING_RESPONSE_LENGTH] = (short) 0;
        }

        short dataLength = (short) 0;
        if (hasCommandData(cmd)) {
            dataLength = receiveData(apdu, buf);
        }
        responseDeferred[0] = hasCommandData(cmd) && isProtocolT0();

        // Setup commands are filtered out by the log
        ApduLog.addCommandLogEntry(buf, (short) 0, (byte) (ISO7816.OFFSET_CDATA + dataLength));

        if (processSetupCommand(apdu, buf, cmd)) {
            return;
        }

        // Blocked card responds to all commands, including SELECT, with 'Function not supported'
        if (cardBlocked) {
            EmvApplet.logAndThrow(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        if (cmd == CMD_SELECT) {
            checkSelect(buf);
            processSelect(apdu, buf);
        } else if (selectingApplet()) {
            return;
        } else if (cmd == CMD_GET_RESPONSE) {
            processGetResponse(apdu, buf);
        } else {
            processCommand(apdu, buf, cmd, dataLength);
        }

        // Status of a response sent in parts is set after the command processing has completed
        short remaining = pendingResponse[PENDING_RESPONSE_LENGTH];
        if (remaining > (short) 0) {
            EmvApplet.logAndThrow((short) (ISO7816.SW_BYTES_REMAINING_00 | (remaining > (short) 0x00FF ? (short) 0 : remaining)));
        }
    }

    /**
     * Check SELECT by DF name (EMV Book 1, 11.3). P2 '00' selects the first and '02' the next occurrence of a partial DF name.
     * The JCRE selects the applet for the first occurrence. Each applet has a single DF name, so there is no next occurrence
     * and a SELECT that did not select this applet did not find a matching file.
     */
    protected void checkSelect(byte[] buf) {
        byte p2 = buf[ISO7816.OFFSET_P2];
        if (buf[ISO7816.OFFSET_P1] != (byte) 0x04 || (p2 != (byte) 0x00 && p2 != (byte) 0x02)) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        if (!selectingApplet()) {
            EmvApplet.logAndThrow(ISO7816.SW_FILE_NOT_FOUND);
        }
    }

    protected void factoryReset(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        factoryReset();

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected void factoryReset() {
        JCSystem.beginTransaction();

        responseTemplateTag = (short) 0x0077;
        randomResponseSuffixData = false;
        cardBlocked = false;
        dataStore.scope = EmvTag.SCOPE_ANY;

        JCSystem.commitTransaction();

        ApduLog.clear();
        ReadRecord.clear();
        EmvTag.clear();
    }

    protected void fuzzReset(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        fuzzReset();

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected void fuzzReset() {
        JCSystem.beginTransaction();

        randomResponseSuffixData = false;
        defaultReadRecord = null;

        JCSystem.commitTransaction();

        EmvTag.clearFuzz();
    }

    protected void consumeLogs(APDU apdu, byte[] buf) {
        short p1p2 = Util.getShort(buf, ISO7816.OFFSET_P1);
        switch (p1p2) {
            case (short) 0x0000:
                ApduLog logEntry = ApduLog.getHead();

                if (logEntry != null) {
                    // hack to omit AID SELECT for reading the logs
                    if (isSelectExchange(logEntry)) {
                        ApduLog.clear();
                        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
                    }

                    Util.arrayCopy(logEntry.getData(), (short) 0, buf, (short) 0, (short) (logEntry.getLength() & 0x00FF));
                    ApduLog.removeLog(logEntry);
                    apdu.setOutgoingAndSend((short) 0, (short) (logEntry.getLength() & 0x00FF));
                } else {
                    ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
                }

                break;
            case (short) 0x0100:
                ApduLog.clear();
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;
        }
    }

    /**
     * True if the log entries from logEntry to the end are a SELECT command and its response,
     * with T=0 the response is '61xx', GET RESPONSE command and the FCI.
     */
    private static boolean isSelectExchange(ApduLog logEntry) {
        if ((logEntry.getLength() & 0x00FF) < 2 || Util.getShort(logEntry.getData(), (short) 0) != CMD_SELECT) {
            return false;
        }

        ApduLog response = logEntry.next;
        if (response != null && response.getLength() == (byte) 2 && response.getData()[0] == (byte) 0x61) {
            ApduLog getResponse = response.next;
            if (getResponse == null || (getResponse.getLength() & 0x00FF) < 2
                || Util.getShort(getResponse.getData(), (short) 0) != CMD_GET_RESPONSE) {
                return false;
            }
            response = getResponse.next;
        }

        return response != null && response == ApduLog.tail;
    }

    /**
     * Set EMV tag of the personalization interface scope. Data objects in the value of a constructed tag, e.g. FCI Proprietary Template (A5),
     * are set as well.
     */
    protected void processSetEmvTag(APDU apdu, byte[] buf, short dataLength) {
        final byte scope = dataStore.scope;
        short tagId = Util.getShort(buf, ISO7816.OFFSET_P1);
        if (tagId == 0x0000) {
            // Tag of one to three bytes is given in the command data before the value, e.g. 'DF 81 01' || value
            if (dataLength == (short) 0 || buf[ISO7816.OFFSET_CDATA] == (byte) 0x00) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            short tagLength = EmvTag.tagEntryLength(buf, (short) ISO7816.OFFSET_CDATA);
            if (tagLength > dataLength) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            short valueOffset = (short) (ISO7816.OFFSET_CDATA + tagLength);
            short valueLength = (short) (dataLength - tagLength);
            EmvTag.setTag(scope, buf, (short) ISO7816.OFFSET_CDATA, buf, valueOffset, (byte) valueLength);
            if (EmvTag.isConstructed(buf, (short) ISO7816.OFFSET_CDATA)) {
                EmvTag.setTags(scope, buf, valueOffset, valueLength);
            }
        } else {
            EmvTag.setTag(scope, tagId, buf, (short) ISO7816.OFFSET_CDATA, (byte) dataLength);
            // First tag byte, P1 is '00' for a one byte tag
            short tagOffset = (buf[ISO7816.OFFSET_P1] == (byte) 0x00) ? (short) ISO7816.OFFSET_P2 : (short) ISO7816.OFFSET_P1;
            if (EmvTag.isConstructed(buf, tagOffset)) {
                EmvTag.setTags(scope, buf, (short) ISO7816.OFFSET_CDATA, dataLength);
            }
        }

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected void processSetEmvTagFuzz(APDU apdu, byte[] buf, short dataLength) {
        short tagId = Util.getShort(buf, ISO7816.OFFSET_P1);

        if (dataLength != (short) 4) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        EmvTag tag = EmvTag.findTag(tagId);
        if (tag == null) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        tag.fuzzOffset     = buf[(short) (ISO7816.OFFSET_CDATA)];
        tag.fuzzLength     = buf[(short) (ISO7816.OFFSET_CDATA + 1)];
        tag.fuzzFlags      = buf[(short) (ISO7816.OFFSET_CDATA + 2)];
        tag.fuzzOccurrence = buf[(short) (ISO7816.OFFSET_CDATA + 3)];

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected void processSetTagTemplate(APDU apdu, byte[] buf, short dataLength) {
        TagTemplate template = null;

        short templateId = Util.getShort(buf, ISO7816.OFFSET_P1);

        // Only GET PROCESSING OPTIONS response has a contactless interface specific template
        if (dataStore.scope == EmvTag.SCOPE_CONTACTLESS && templateId != (short) 0x0001) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        switch (templateId) {
            case 0x0001:
                template = (dataStore.scope == EmvTag.SCOPE_CONTACTLESS)
                    ? responseTemplateGetProcessingOptionsContactless : responseTemplateGetProcessingOptions;
                break;
            case 0x0002:
                template = responseTemplateDda;
                break;
            case 0x0003:
                template = responseTemplateGenerateAc;
                break;
            case 0x0004:
                template = tag6fFci;
                break;
            case 0x0005:
                template = tagA5Fci;
                break;
            case 0x0006:
                template = tagBf0cFci;
                break;
            default:
                template = getTagTemplate(templateId);
                break;
        }

        if (template == null) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        template.setData(buf, (short) ISO7816.OFFSET_CDATA, (byte) dataLength);

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * Application specific tag templates, null if templateId is not supported.
     */
    protected TagTemplate getTagTemplate(short templateId) {
        return null;
    }

    protected void processSetReadRecordTemplate(APDU apdu, byte[] buf, short dataLength) {
        short readRecordId = Util.getShort(buf, ISO7816.OFFSET_P1);

        if (readRecordId == 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        ReadRecord.setRecord(readRecordId, buf, (short) ISO7816.OFFSET_CDATA, (byte) dataLength);

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * Set READ RECORD response as is: record template '70' with the data objects of the record, e.g. a personalization data
     * grouping of the record (EMV Card Personalization Specification). P1 is the record number and P2 the SFI as in READ RECORD.
     * Data objects of the record are set as EMV tags of the personalization interface scope for the card processing, e.g. CDOL1.
     */
    protected void processSetReadRecordData(APDU apdu, byte[] buf, short dataLength) {
        short readRecordId = Util.getShort(buf, ISO7816.OFFSET_P1);
        if (readRecordId == 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Record template: '70' || length (one byte or '81' || one byte) || data objects
        short offset = (short) ISO7816.OFFSET_CDATA;
        if (dataLength < (short) 2 || buf[offset] != (byte) 0x70) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        short valueOffset = (short) (offset + 2);
        short valueLength = (short) (buf[(short) (offset + 1)] & 0x00FF);
        if (valueLength == (short) 0x81 && dataLength > (short) 2) {
            valueOffset++;
            valueLength = (short) (buf[(short) (offset + 2)] & 0x00FF);
        } else if (valueLength > (short) 0x7F) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if ((short) (valueOffset - offset + valueLength) != dataLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        EmvTag.setTags(dataStore.scope, buf, valueOffset, valueLength);
        ReadRecord.setRecord(readRecordId, buf, offset, (byte) dataLength, true);

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * Build FCI tag from its template. Template without tag list keeps the stored tag.
     */
    protected void expandFciTemplate(TagTemplate template, short tagId) {
        if (template.getLength() != (byte) 0) {
            short length = template.expandTlvToArray(tmpBuffer, (short) 0);
            EmvTag.setTag(tagId, tmpBuffer, (short) 0, (byte) length);
        }
    }

    protected void sendResponseTemplate(APDU apdu, byte[] buf, TagTemplate template) {
        sendResponseTemplate(apdu, buf, template, responseTemplateTag);
    }

    protected void sendResponseTemplate(APDU apdu, byte[] buf, TagTemplate template, short responseTemplateTag) {
        short templateTagLength = (short) 0;

        if (responseTemplateTag == (short) 0x0077) {
            // Template 2, tag 77
            templateTagLength = template.expandTlvToArray(responseBuffer, RESPONSE_TEMPLATE_HEADER_LENGTH);
        } else if (responseTemplateTag == (short) 0x0080) {
            // Template 1, tag 80
            templateTagLength = template.expandTagDataToArray(responseBuffer, RESPONSE_TEMPLATE_HEADER_LENGTH);
        } else {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }
        templateTagLength -= RESPONSE_TEMPLATE_HEADER_LENGTH;

        if (templateTagLength <= (short) 0x00FF) {
            EmvTag.setTag(responseTemplateTag, responseBuffer, RESPONSE_TEMPLATE_HEADER_LENGTH, (byte) templateTagLength);
            sendResponse(apdu, buf, responseTemplateTag);
            return;
        }

        // Value does not fit an EmvTag, send the template with a three byte length
        responseBuffer[0] = (byte) responseTemplateTag;
        responseBuffer[1] = (byte) 0x82;
        Util.setShort(responseBuffer, (short) 2, templateTagLength);
        sendResponse(apdu, buf, responseBuffer, (short) 0, (short) (RESPONSE_TEMPLATE_HEADER_LENGTH + templateTagLength));
    }

    protected void sendResponse(APDU apdu, byte[] buf, short tagId) {
        EmvTag tag = EmvTag.findTag(tagId);
        if (tag == null) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        short dataLength = tag.copyToArray(responseBuffer, (short) 0);

        sendResponse(apdu, buf, responseBuffer, (short) 0, dataLength);
    }

    protected void sendResponse(APDU apdu, byte[] buf, byte[] data, short dataOffset, short length) {
        boolean deferred = responseDeferred[0] && length > (short) 0;
        if (deferred || length > MAX_RESPONSE_PART_LENGTH) {
            // Response data in the APDU buffer is at the command data offset
            short offset = (data == buf) ? (short) ISO7816.OFFSET_CDATA : dataOffset;
            Util.arrayCopy(data, offset, responseBuffer, (short) 0, length);
            pendingResponse[PENDING_RESPONSE_OFFSET] = (short) 0;
            pendingResponse[PENDING_RESPONSE_LENGTH] = length;
            if (!deferred) {
                sendResponsePart(apdu, buf, MAX_RESPONSE_PART_LENGTH);
            }
            return;
        }

        // Response data in the APDU buffer is at the command data offset, sent from the buffer start to allow the maximum length
        short offset = (data == buf) ? (short) ISO7816.OFFSET_CDATA : dataOffset;
        Util.arrayCopyNonAtomic(data, offset, buf, (short) 0, length);

        ApduLog.addLogEntry(buf, (short) 0, (byte) length);
        apdu.setOutgoingAndSend((short) 0, length);
    }

    /**
     * Send next part of the pending response data. When data remains, process sets status '61xx', xx is the remaining length or '00' if over 255.
     */
    private void sendResponsePart(APDU apdu, byte[] buf, short maxLength) {
        short offset = pendingResponse[PENDING_RESPONSE_OFFSET];
        short remaining = pendingResponse[PENDING_RESPONSE_LENGTH];
        short length = (remaining < maxLength) ? remaining : maxLength;

        Util.arrayCopyNonAtomic(responseBuffer, offset, buf, (short) 0, length);
        remaining -= length;
        pendingResponse[PENDING_RESPONSE_OFFSET] = (short) (offset + length);
        pendingResponse[PENDING_RESPONSE_LENGTH] = remaining;

        ApduLog.addLogEntry(buf, (short) 0, (byte) length);
        apdu.setOutgoingAndSend((short) 0, length);
    }

    /**
     * GET RESPONSE (ISO/IEC 7816-4, 7.6.1) returns the next part of the response data, at most Le bytes.
     * With T=0, P3 longer than the remaining data is answered with '6Cxx'.
     */
    protected void processGetResponse(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x0000) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        short remaining = pendingResponse[PENDING_RESPONSE_LENGTH];
        if (remaining == (short) 0) {
            EmvApplet.logAndThrow(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short expectedLength = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
        if (isProtocolT0() && remaining <= MAX_RESPONSE_PART_LENGTH && (expectedLength == (short) 0 || expectedLength > remaining)) {
            EmvApplet.logAndThrow((short) (ISO7816.SW_CORRECT_LENGTH_00 | remaining));
        }

        // Le '00' is the maximum
        if (expectedLength == (short) 0 || expectedLength > MAX_RESPONSE_PART_LENGTH) {
            expectedLength = MAX_RESPONSE_PART_LENGTH;
        }

        sendResponsePart(apdu, buf, expectedLength);
    }

    /**
     * Serialize READ RECORD tag 70 value to array.
     */
    protected short expandReadRecord(ReadRecord readRecord, byte[] dst, short dstOffset) {
        return readRecord.expandTlvToArray(dst, dstOffset);
    }

    /**
     * READ RECORD response of a record set as is: the record template '70' as personalized, except the primitive data objects of
     * the template that the card has generated have their current value, e.g. Card Authentication Related Data (9F69) of fDDA that
     * is signed in GET PROCESSING OPTIONS and read by the terminal from the record. Padding and other data objects are kept as is.
     */
    private short copyRawRecord(ReadRecord readRecord, byte[] dst) {
        final short end = readRecord.copyDataToArray(tmpBuffer, (short) 0);

        // Record template is validated when personalized: '70' || length (one byte or '81' || one byte) || data objects
        short offset = (tmpBuffer[1] == (byte) 0x81) ? (short) 3 : (short) 2;

        // Data objects are written after room for the longest template header, '70' '82' || two byte length
        final short valueOffset = (short) 4;
        short dstOffset = valueOffset;
        while (offset < end) {
            if (tmpBuffer[offset] == (byte) 0x00 || tmpBuffer[offset] == (byte) 0xFF) {
                dst[dstOffset] = tmpBuffer[offset];
                dstOffset++;
                offset++;
                continue;
            }

            final short tagOffset = offset;
            offset += EmvTag.tagEntryLength(tmpBuffer, offset);
            short valueLength = (short) (tmpBuffer[offset] & 0x00FF);
            offset++;
            if (valueLength == (short) 0x81) {
                valueLength = (short) (tmpBuffer[offset] & 0x00FF);
                offset++;
            }
            offset += valueLength;

            EmvTag tag = null;
            if (!EmvTag.isConstructed(tmpBuffer, tagOffset)) {
                tag = EmvTag.findTag(tmpBuffer, tagOffset);
            }
            if (tag != null && tag.isGenerated()) {
                dstOffset = tag.copyToArray(dst, dstOffset);
            } else {
                dstOffset = Util.arrayCopyNonAtomic(tmpBuffer, tagOffset, dst, dstOffset, (short) (offset - tagOffset));
            }
        }

        short length = (short) (dstOffset - valueOffset);
        short headerOffset;
        if (length < (short) 0x80) {
            headerOffset = (short) (valueOffset - 2);
            dst[(short) (headerOffset + 1)] = (byte) length;
        } else if (length <= (short) 0xFF) {
            headerOffset = (short) (valueOffset - 3);
            dst[(short) (headerOffset + 1)] = (byte) 0x81;
            dst[(short) (headerOffset + 2)] = (byte) length;
        } else {
            headerOffset = (short) 0;
            dst[1] = (byte) 0x82;
            Util.setShort(dst, (short) 2, length);
        }
        dst[headerOffset] = (byte) 0x70;

        return Util.arrayCopyNonAtomic(dst, headerOffset, dst, (short) 0, (short) (dstOffset - headerOffset));
    }

    protected void processReadRecord(APDU apdu, byte[] buf) {
        short p1p2 = Util.getShort(buf, ISO7816.OFFSET_P1);

        ReadRecord readRecord = ReadRecord.findRecord(p1p2);
        if (readRecord == null) {
            if (defaultReadRecord != null) {
                short p1p2Fallback = Util.getShort(defaultReadRecord, (short) 0);
                readRecord = ReadRecord.findRecord(p1p2Fallback);
            }

            if (readRecord == null) {
                EmvApplet.logAndThrow(ISO7816.SW_RECORD_NOT_FOUND);
            }
        }

        short dataLength;
        if (readRecord.isRaw()) {
            dataLength = copyRawRecord(readRecord, responseBuffer);
        } else {
            short tag70Length = expandReadRecord(readRecord, tmpBuffer, (short) 0);

            EmvTag tag = EmvTag.setTag((short) 0x0070, tmpBuffer, (short) 0, (byte) tag70Length);

            dataLength = tag.copyToArray(responseBuffer, (short) 0);
        }

        checkExpectedLength(buf, dataLength);

        sendResponse(apdu, buf, responseBuffer, (short) 0, dataLength);
    }

    protected EmvApplet() {
        tmpBuffer = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_DESELECT);
        if (responseBuffer == null) {
            responseBuffer = JCSystem.makeTransientByteArray(RESPONSE_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        }
        pendingResponse = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        responseDeferred = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_DESELECT);

        dataStore = new DataStore();
        DataStore.current = dataStore;

        factoryReset();

        responseTemplateGetProcessingOptions = new TagTemplate();
        responseTemplateGetProcessingOptionsContactless = new TagTemplate();
        responseTemplateDda = new TagTemplate();
        responseTemplateGenerateAc = new TagTemplate();
        tag6fFci = new TagTemplate();
        tagA5Fci = new TagTemplate();
        tagBf0cFci = new TagTemplate();

        // FCI: DF Name (84) and FCI Proprietary Template (A5), EMV Book 1, 11.3.4
        tag6fFci.setData(DEFAULT_FCI_TEMPLATE, (short) 0, (byte) DEFAULT_FCI_TEMPLATE.length);

        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }
}
