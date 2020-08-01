package emvcardsimulator;

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
 
public class PaymentApplicationTest {
    private static final byte[] APPLET_AID = new byte[] { (byte) 0xAF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x12, (byte) 0x34 };

    @BeforeAll
    public static void setup() throws CardException {
        SmartCard.connect();
        SmartCard.install(APPLET_AID, PaymentApplicationContainer.class);
    }

    @AfterAll
    public static void disconnect() throws CardException {
        SmartCard.disconnect();
    }

    @Test
    public void selectTest() throws CardException {
        ResponseAPDU response = SmartCard.transmitCommand(new byte[] { (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x07, (byte) 0xAF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x12, (byte) 0x34 });
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

        // Reset card setup
        response = SmartCard.transmitCommand(new byte[] {(byte) 0xE0, (byte) 0x05, (byte) 0x00, (byte) 0x00, (byte) 0x00});
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());
    }
}
