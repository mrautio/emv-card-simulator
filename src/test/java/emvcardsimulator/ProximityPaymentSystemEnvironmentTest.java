package emvcardsimulator;

import static emvcardsimulator.EmvTestUtil.assertSw;
import static emvcardsimulator.EmvTestUtil.hex;
import static emvcardsimulator.EmvTestUtil.send;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.IOException;
import javacard.framework.ISO7816;
import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Proximity Payment System Environment (EMV Contactless Book B) and SELECT processing.
 */
public class ProximityPaymentSystemEnvironmentTest {
    // 2PAY.SYS.DDF01
    private static final byte[] PPSE_AID = hex("32 50 41 59 2E 53 59 53 2E 44 44 46 30 31");
    private static final String SETUP_FILE = "../config/card_setup_ppse_apdus.yaml";

    private static final String SELECT_PPSE = "00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00";
    private static final String DIRECTORY_ENTRY =
        "61 1F 4F 07 AF FF FF FF FF 12 34 50 0D 56 45 53 41 20 45 4C 45 43 54 52 4F 4E 87 01 01 9F 2A 01 03";

    @BeforeEach
    public void setup() throws CardException, IOException {
        EmvTestUtil.installAndPersonalize(PPSE_AID, ProximityPaymentSystemEnvironment.class, SETUP_FILE);
    }

    @AfterEach
    public void disconnect() throws CardException {
        SmartCard.disconnect();
        SmartCard.setLogging(true);
    }

    @Test
    public void selectTest() throws CardException {
        ResponseAPDU response = send(SELECT_PPSE);
        assertSw(0x9000, response);
        assertArrayEquals(hex("6F 36 84 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 A5 24 BF 0C 21 " + DIRECTORY_ENTRY), response.getData());
    }

    @Test
    public void severalDirectoryEntriesTest() throws CardException {
        // Second contactless application with Kernel Identifier '02'
        String secondEntry = "61 10 4F 07 AF FF FF FF FF 56 78 87 01 02 9F 2A 01 02";
        assertSw(0x9000, send("80 01 BF 0C 33 " + DIRECTORY_ENTRY + " " + secondEntry));

        ResponseAPDU response = send(SELECT_PPSE);
        assertSw(0x9000, response);
        assertArrayEquals(hex("6F 48 84 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 A5 36 BF 0C 33 " + DIRECTORY_ENTRY + " " + secondEntry),
            response.getData());
    }

    @Test
    public void partialSelectTest() throws CardException {
        // JCRE selects the applet by partial DF name
        ResponseAPDU response = send("00 A4 04 00 05 32 50 41 59 2E 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("6F"), new byte[] { response.getData()[0] });

        // No next occurrence of the DF name
        assertSw(ISO7816.SW_FILE_NOT_FOUND, send("00 A4 04 02 05 32 50 41 59 2E 00"));
    }

    @Test
    public void selectParametersTest() throws CardException {
        assertSw(0x9000, send(SELECT_PPSE));

        assertSw(ISO7816.SW_INCORRECT_P1P2, send("00 A4 00 00 02 3F 00 00"));
        assertSw(ISO7816.SW_INCORRECT_P1P2, send("00 A4 04 04 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00"));
    }

    @Test
    public void readRecordNotSupportedTest() throws CardException {
        assertSw(0x9000, send(SELECT_PPSE));

        // PPSE has no records
        assertSw(ISO7816.SW_INS_NOT_SUPPORTED, send("00 B2 01 0C 00"));
    }
}
