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
    protected static final short CMD_FACTORY_RESET             = (short) 0x8005;
    protected static final short CMD_LOG_CONSUME               = (short) 0x8006;
    protected static final short CMD_FUZZ_RESET                = (short) 0x8007;
    protected static final short CMD_SELECT = (short) 0x00A4;
    protected static final short CMD_READ_RECORD = (short) 0x00B2;
    protected static final short CMD_DDA = (short) 0x0088;
    protected static final short CMD_VERIFY_PIN = (short) 0x0020;
    protected static final short CMD_GET_CHALLENGE = (short) 0x0084;
    protected static final short CMD_GET_DATA = (short) 0x80CA;
    protected static final short CMD_GET_PROCESSING_OPTIONS = (short) 0x80A8;
    protected static final short CMD_GENERATE_AC = (short) 0x80AE;
    protected static final short CMD_EXTERNAL_AUTHENTICATE = (short) 0x0082;

    protected static final short SW_AUTHENTICATION_METHOD_BLOCKED = (short) 0x6983;
    protected static final short SW_REFERENCED_DATA_NOT_FOUND = (short) 0x6A88;

    public static RandomData randomData;
    public static byte[] tmpBuffer;

    protected static void logAndThrow(short responseTrailer) {
        ApduLog.addLogEntry(responseTrailer);
        ISOException.throwIt(responseTrailer);
    }

    protected EmvTag emvTags;
    protected ReadRecord readRecords;

    protected TagTemplate responseTemplateGetProcessingOptions;
    protected TagTemplate responseTemplateDda;
    protected TagTemplate responseTemplateGenerateAc;
    protected TagTemplate tag6fFci;
    protected TagTemplate tagA5Fci;
    protected TagTemplate tagBf0cFci;

    protected byte[] defaultReadRecord;


    protected short responseTemplateTag;
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
                return true;
            default:
                return false;
        }
    }

    /**
     * Validate CLA and return CLA || INS with the logical channel bits cleared.
     */
    protected static short getCommand(byte[] buf) {
        byte cla = buf[ISO7816.OFFSET_CLA];

        // Only the first interindustry class (000x xxxx) and its proprietary counterpart (100x xxxx) are supported
        if ((cla & (byte) 0x60) != 0) {
            ApduLog.addCommandLogEntry(buf, (short) 0, ISO7816.OFFSET_CDATA);
            EmvApplet.logAndThrow(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // Secure messaging indication bits
        if ((cla & (byte) 0x0C) != 0) {
            ApduLog.addCommandLogEntry(buf, (short) 0, ISO7816.OFFSET_CDATA);
            EmvApplet.logAndThrow(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
        }

        return Util.makeShort((byte) (cla & (byte) 0x80), buf[ISO7816.OFFSET_INS]);
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
     * Check Le of a case 2 command against the response length. Le 0x00 accepts any response length.
     */
    protected static void checkExpectedLength(byte[] buf, short responseLength) {
        short expectedLength = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
        if (expectedLength != 0 && expectedLength != responseLength) {
            EmvApplet.logAndThrow((short) (ISO7816.SW_CORRECT_LENGTH_00 | (responseLength & 0x00FF)));
        }
    }

    /**
     * Find a tag from data object list (DOL) stored in EmvTag dolTagId.
     * Returns the offset of the tag value in DOL related data, or -1 if not found.
     * When searchTagId is 0, returns the total length of DOL related data, or -1 if the DOL does not exist.
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
        byte[] buf = apdu.getBuffer();

        short cmd = getCommand(buf);

        short dataLength = (short) 0;
        if (hasCommandData(cmd)) {
            dataLength = receiveData(apdu, buf);
        }

        // Setup commands are filtered out by the log
        ApduLog.addCommandLogEntry(buf, (short) 0, (byte) (ISO7816.OFFSET_CDATA + dataLength));

        if (processSetupCommand(apdu, buf, cmd)) {
            return;
        }

        if (cmd == CMD_SELECT) {
            processSelect(apdu, buf);
            return;
        }

        if (selectingApplet()) {
            return;
        }

        processCommand(apdu, buf, cmd, dataLength);
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
                    if (logEntry.next == ApduLog.tail && Util.getShort(logEntry.getData(), (short) 0) == 0x00A4) {
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

    protected void processSetEmvTag(APDU apdu, byte[] buf, short dataLength) {
        short tagId = Util.getShort(buf, ISO7816.OFFSET_P1);
        if (tagId == 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        EmvTag.setTag(tagId, buf, (short) ISO7816.OFFSET_CDATA, (byte) dataLength);

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

        switch (templateId) {
            case 0x0001:
                template = responseTemplateGetProcessingOptions;
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
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if (template == null) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        template.setData(buf, (short) ISO7816.OFFSET_CDATA, (byte) dataLength);

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected void processSetReadRecordTemplate(APDU apdu, byte[] buf, short dataLength) {
        short readRecordId = Util.getShort(buf, ISO7816.OFFSET_P1);

        if (readRecordId == 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        ReadRecord.setRecord(readRecordId, buf, (short) ISO7816.OFFSET_CDATA, (byte) dataLength);

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected void sendResponseTemplate(APDU apdu, byte[] buf, TagTemplate template) {
        sendResponseTemplate(apdu, buf, template, responseTemplateTag);
    }

    protected void sendResponseTemplate(APDU apdu, byte[] buf, TagTemplate template, short responseTemplateTag) {
        short templateTagLength = (short) 0;

        if (responseTemplateTag == (short) 0x0077) {
            // Template 2, tag 77
            templateTagLength = template.expandTlvToArray(tmpBuffer, (short) 0);
        } else if (responseTemplateTag == (short) 0x0080) {
            // Template 1, tag 80
            templateTagLength = template.expandTagDataToArray(tmpBuffer, (short) 0);
        } else {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        EmvTag.setTag(responseTemplateTag, tmpBuffer, (short) 0, (byte) templateTagLength);
        sendResponse(apdu, buf, responseTemplateTag);
    }

    protected void sendResponse(APDU apdu, byte[] buf, short tagId) {
        EmvTag tag = EmvTag.findTag(tagId);
        if (tag == null) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        short dataOffset = tag.copyToArray(buf, (short) ISO7816.OFFSET_CDATA);
        short dataLength = (short) (dataOffset - ISO7816.OFFSET_CDATA);

        sendResponse(apdu, buf, buf, (short) 0, dataLength);
    }

    protected void sendResponse(APDU apdu, byte[] buf, byte[] data, short dataOffset, short length) {
        if (data != buf) {
            Util.arrayCopy(data, dataOffset, buf, ISO7816.OFFSET_CDATA, length);
        }

        ApduLog.addLogEntry(buf, ISO7816.OFFSET_CDATA, (byte) length);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, length);
    }

    /**
     * Serialize READ RECORD tag 70 value to array.
     */
    protected short expandReadRecord(ReadRecord readRecord, byte[] dst, short dstOffset) {
        return readRecord.expandTlvToArray(dst, dstOffset);
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

        short tag70Length = expandReadRecord(readRecord, tmpBuffer, (short) 0);

        EmvTag tag = EmvTag.setTag((short) 0x0070, tmpBuffer, (short) 0, (byte) tag70Length);

        short dataLength = (short) (tag.copyToArray(buf, (short) ISO7816.OFFSET_CDATA) - ISO7816.OFFSET_CDATA);

        checkExpectedLength(buf, dataLength);

        sendResponse(apdu, buf, buf, (short) 0, dataLength);
    }

    protected EmvApplet() {
        tmpBuffer = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_DESELECT);
        
        factoryReset();

        responseTemplateGetProcessingOptions = new TagTemplate();
        responseTemplateDda = new TagTemplate();
        responseTemplateGenerateAc = new TagTemplate();
        tag6fFci = new TagTemplate();
        tagA5Fci = new TagTemplate();
        tagBf0cFci = new TagTemplate();

        //emvTags = EmvTag.setTag((short) 0x00, tmpBuffer, (short) 0, (byte) 0);

        //readRecords = ReadRecord.setRecord((short) 0x00, tmpBuffer, (short) 0, (byte) 0);

        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }
}
