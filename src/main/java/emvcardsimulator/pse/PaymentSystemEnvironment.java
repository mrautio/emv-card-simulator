package emvcardsimulator.pse;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;


public class PaymentSystemEnvironment extends Applet {

    private static final byte[] SELECT_RESPONSE = {
        (byte) 0x6f, (byte) 0x20, (byte) 0x84, (byte) 0x0e
    };
    private static final byte[] READ_RECORDS_1 = {
        (byte) 0x70, (byte) 0x23, (byte) 0x61, (byte) 0x21
    };
    private static final byte[] READ_RECORDS_2 = {
        (byte) 0x70, (byte) 0x25, (byte) 0x61, (byte) 0x23
    };

    private static final byte INS_READ_RECORD = (byte) 0xb2;

    public static void install(byte[] buffer, short offset, byte length) {
        (new PaymentSystemEnvironment()).register();
    }

    private void processSelect(APDU apdu, byte[] buf) {
        Util.arrayCopy(SELECT_RESPONSE, (byte)  0, buf, ISO7816.OFFSET_CDATA, (byte)  SELECT_RESPONSE.length);
        apdu.setOutgoingAndSend(
                ISO7816.OFFSET_CDATA, (byte)  SELECT_RESPONSE.length);
    }

    private void processReadRecord(APDU apdu, byte[] buf) {
        if (selectingApplet()) {
            return;
        }

        if (buf[ISO7816.OFFSET_P2] != 0x14) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (buf[ISO7816.OFFSET_LC] != 0x00) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        byte record = (byte) (buf[ISO7816.OFFSET_P1] - 1);
        byte[] readRecord = null;
        switch (record) {
            case 0x00:
                readRecord = READ_RECORDS_1;
                break;
            case 0x01:
                readRecord = READ_RECORDS_2;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
                break;
        }

        Util.arrayCopy(readRecord, (byte)  0, buf, ISO7816.OFFSET_CDATA, (byte)  readRecord.length);
        apdu.setOutgoingAndSend(
                ISO7816.OFFSET_CDATA, (byte)  readRecord.length);
    }

    /**
     * Process PSE application selection and read records.
     */
    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer(); 

        if (buf[ISO7816.OFFSET_CLA] != ISO7816.CLA_ISO7816) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buf[ISO7816.OFFSET_INS]) {
            case ISO7816.INS_SELECT:
                processSelect(apdu, buf);
                break;
            case INS_READ_RECORD:
                processReadRecord(apdu, buf);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
