package emvcardsimulator;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class PaymentSystemEnvironment extends EmvApplet {

    private static final byte[] SELECT_RESPONSE = {
        (byte) 0x6F, (byte) 0x2C, (byte) 0x84, (byte) 0x0E, (byte) 0x31, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E, (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E, (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31, (byte) 0xA5, (byte) 0x1A, (byte) 0x88, (byte) 0x01, (byte) 0x01,  (byte) 0x5F, (byte) 0x2D, (byte) 0x02, (byte) 0x65, (byte) 0x6E,  (byte) 0x9F, (byte) 0x11, (byte) 0x01, (byte) 0x01,  (byte) 0xBF, (byte) 0x0C, (byte) 0x0B,  (byte) 0xDF, (byte) 0x02, (byte) 0x02, (byte) 0x02, (byte) 0x46,  (byte) 0xDF, (byte) 0x47, (byte) 0x03, (byte) 0x80, (byte) 0x01, (byte) 0x01
    };
    private static final byte[] READ_RECORDS_1 = {
        (byte) 0x70, (byte) 0x30, (byte) 0x61, (byte) 0x2E,  (byte) 0x4F, (byte) 0x07, (byte) 0xAF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,  (byte) 0xFF, (byte) 0x12, (byte) 0x34, (byte) 0x50, (byte) 0x0D, (byte) 0x56, (byte) 0x45, (byte) 0x53, (byte) 0x41, (byte) 0x20, (byte) 0x45, (byte) 0x4C, (byte) 0x45, (byte) 0x43, (byte) 0x54, (byte) 0x52,  (byte) 0x4F, (byte) 0x4E,  (byte) 0x9F, (byte) 0x12, (byte) 0x10, (byte) 0x56, (byte) 0x45, (byte) 0x53, (byte) 0x41, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x87, (byte) 0x01, (byte) 0x01
    };

    public static void install(byte[] buffer, short offset, byte length) {
        (new PaymentSystemEnvironment()).register();
    }

    private void processSetSettings(APDU apdu, byte[] buf) {
        short settingsId = Util.getShort(buf, ISO7816.OFFSET_P1);
        switch (settingsId) {
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

    public PaymentSystemEnvironment() {
        super();
    }

    private void processSelect(APDU apdu, byte[] buf) {
        // Check if AID (tag 84) exists in the ICC
        if (EmvTag.findTag((short) 0x84) != null) {
            if (tagBf0cFci != null) {
                short length = tagBf0cFci.expandTlvToArray(tmpBuffer, (short) 0);
                EmvTag.setTag((short) 0xBF0C, tmpBuffer, (short) 0, (byte) length);
            }

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

        short tag70Length = readRecord.copyDataToArray(tmpBuffer, (short) 0);

        EmvTag tag = EmvTag.setTag((short) 0x0070, tmpBuffer, (short) 0, (byte) tag70Length);

        if (buf[ISO7816.OFFSET_LC] != (byte) 0x00 && buf[ISO7816.OFFSET_LC] != tag.getLength()) {
            EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
        }

        sendResponse(apdu, buf, (short) 0x0070);
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
            default:
                EmvApplet.logAndThrow(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
