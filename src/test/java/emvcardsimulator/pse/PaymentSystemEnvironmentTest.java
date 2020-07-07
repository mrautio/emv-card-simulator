package emvcardsimulator.pse;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.licel.jcardsim.utils.AIDUtil;

import emvcardsimulator.SmartCard;

import javacard.framework.ISO7816;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
 
public class PaymentSystemEnvironmentTest {

    private static final String APPLET_AID = "1PAY.SYS.DDF01";

    private static final byte[] SELECT_RESPONSE = {
        (byte) 0x6f, (byte) 0x20, (byte) 0x84, (byte) 0x0e
    };
    private static final byte[][] READ_RECORDS = {
        {
            (byte) 0x70, (byte) 0x23, (byte) 0x61, (byte) 0x21
        },
        {
            (byte) 0x70, (byte) 0x25, (byte) 0x61, (byte) 0x23
        }
    };

    @BeforeAll
    public static void setup() throws CardException {
        SmartCard.connect();
        SmartCard.install(APPLET_AID, PaymentSystemEnvironmentContainer.class);
    }

    @AfterAll
    public static void disconnect() throws CardException {
        SmartCard.disconnect();
    }

    @Test
    public void selectTest() throws CardException {
        ResponseAPDU response = SmartCard.select(APPLET_AID);
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());
        assertArrayEquals(SELECT_RESPONSE, response.getData());
    }

    @Test
    public void readRecordTest() throws CardException {
        selectTest();

        for (int i = 0; i < 5; i++) {
            ResponseAPDU response = SmartCard.transmitCommand(new byte[] { ISO7816.CLA_ISO7816, (byte) 0xB2, (byte) i, (byte) 0x14, (byte) 0x00 });

            switch (i) {
                case 1:
                case 2:
                    assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());
                    assertArrayEquals(READ_RECORDS[i - 1], response.getData());
                    break;
                default:
                    assertEquals(ISO7816.SW_RECORD_NOT_FOUND, (short) response.getSW());
                    break;
            }
            //
        }
    }
}
