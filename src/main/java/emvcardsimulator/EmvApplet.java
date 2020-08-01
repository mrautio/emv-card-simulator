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
    /*
    // for dev "debugging"
    protected void printAsHex(String type, byte[] buf) {
        printAsHex(type, buf, 0, buf.length);
    }
    protected void printAsHex(String type, byte[] buf, int offset, int length) {
        System.out.println(String.format("%s [%02X] %s", type, length, toHexString(buf, offset, length)));
    }
    protected String toHexString(byte[] buf, int offset, int length) {
        String result = "[";
        for(int i = offset; i < offset+length-1; i++) {
            result += String.format("%02X, ", buf[i]);
        }
        result += String.format("%02X]", buf[offset+length-1]);

        return result;
    }

    protected void printEmvTags() {
        for (EmvTag iter = EmvTag.getHead(); iter != null; iter = iter.getNext()) {
            printAsHex(toHexString(iter.getTag(), 0, 2), iter.getData(), 0, (iter.getLength() & 0x00FF));
        }
    }
    */

    protected static final short CMD_SET_SETTINGS              = (short) 0xE000;
    protected static final short CMD_SET_EMV_TAG               = (short) 0xE001;
    protected static final short CMD_SET_TAG_TEMPLATE          = (short) 0xE002;
    protected static final short CMD_SET_READ_RECORD_TEMPLATE  = (short) 0xE003;
    protected static final short CMD_FACTORY_RESET             = (short) 0xE005;
    protected static final short CMD_SELECT = (short) 0x00A4;
    protected static final short CMD_READ_RECORD = (short) 0x00B2;
    protected static final short CMD_DDA = (short) 0x0088;
    protected static final short CMD_VERIFY_PIN = (short) 0x0020;
    protected static final short CMD_GET_CHALLENGE = (short) 0x0084;
    protected static final short CMD_GET_DATA = (short) 0x80CA;
    protected static final short CMD_GET_PROCESSING_OPTIONS = (short) 0x80A8;
    protected static final short CMD_GENERATE_AC = (short) 0x80AE;

    protected RandomData randomData;
    protected byte[] tmpBuffer;

    protected EmvTag emvTags;
    protected ReadRecord readRecords;

    protected TagTemplate responseTemplateGetProcessingOptions;
    protected TagTemplate responseTemplateDda;
    protected TagTemplate responseTemplateGenerateAc;
    protected TagTemplate tag6fFci;
    protected TagTemplate tagA5Fci;
    protected TagTemplate tagBf0cFci;


    protected short responseTemplateTag;
    protected boolean randomResponseSuffixData;

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

        ReadRecord.clear();
    }

    protected void processSetEmvTag(APDU apdu, byte[] buf) {
        short tagId = Util.getShort(buf, ISO7816.OFFSET_P1);
        if (tagId == 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        EmvTag tag = EmvTag.setTag(tagId, buf, (short) ISO7816.OFFSET_CDATA, buf[ISO7816.OFFSET_LC]);

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected void processSetTagTemplate(APDU apdu, byte[] buf) {
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

        template.setData(buf, (short) ISO7816.OFFSET_CDATA, buf[ISO7816.OFFSET_LC]);

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected void processSetReadRecordTemplate(APDU apdu, byte[] buf) {
        short readRecordId = Util.getShort(buf, ISO7816.OFFSET_P1);

        if (readRecordId == 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        ReadRecord.setRecord(readRecordId, buf, (short) ISO7816.OFFSET_CDATA, buf[ISO7816.OFFSET_LC]);

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected void sendResponseTemplate(APDU apdu, byte[] buf, TagTemplate template) {
        short templateTagLength = (short) 0;

        if (responseTemplateTag == (short) 0x0077) {
            // Template 2, tag 77
            templateTagLength = template.expandTlvToArray(tmpBuffer, (short) 0);
        } else if (responseTemplateTag == (short) 0x0080) {
            // Template 1, tag 80
            templateTagLength = template.expandTagDataToArray(tmpBuffer, (short) 0);
        } else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        EmvTag.setTag(responseTemplateTag, tmpBuffer, (short) 0, (byte) templateTagLength);
        sendResponse(apdu, buf, responseTemplateTag);
    }

    protected void sendResponse(APDU apdu, byte[] buf, short tagId) {
        EmvTag tag = EmvTag.findTag(tagId);
        if (tag == null) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short dataOffset = tag.copyToArray(buf, (short) ISO7816.OFFSET_CDATA);
        short dataLength = (short) (dataOffset - ISO7816.OFFSET_CDATA);

        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLength);
    }

    protected void sendResponse(APDU apdu, byte[] buf, byte[] data) {
        short length = (short) data.length;
        if (randomResponseSuffixData) {
            short maxLength = (short) ((buf.length - ISO7816.OFFSET_CDATA) & 0x00FF);

            randomData.generateData(buf, (short) ISO7816.OFFSET_CDATA, maxLength);

            short extraLength = (short) (buf[ISO7816.OFFSET_CDATA] & 0x00FF);
            length += extraLength;

            if (length > maxLength) {
                length = maxLength;
            }
        }

        Util.arrayCopy(data, (short) 0, buf, ISO7816.OFFSET_CDATA, (short) data.length);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, length);
    }

    protected void processReadRecord(APDU apdu, byte[] buf) {
        short p1p2 = Util.getShort(buf, ISO7816.OFFSET_P1);

        ReadRecord readRecord = ReadRecord.findRecord(p1p2);
        if (readRecord == null) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }

        short tag70Length = readRecord.expandTlvToArray(tmpBuffer, (short) 0);

        EmvTag tag = EmvTag.setTag((short) 0x0070, tmpBuffer, (short) 0, (byte) tag70Length);

        if (buf[ISO7816.OFFSET_LC] != (byte) 0x00 && buf[ISO7816.OFFSET_LC] != tag.getLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        sendResponse(apdu, buf, (short) 0x0070);
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

        emvTags = EmvTag.setTag((short) 0x00, tmpBuffer, (short) 0, (byte) 0);

        readRecords = ReadRecord.setRecord((short) 0x00, tmpBuffer, (short) 0, (byte) 0);

        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }
}
