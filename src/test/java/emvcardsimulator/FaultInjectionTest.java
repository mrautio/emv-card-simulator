package emvcardsimulator;

import static emvcardsimulator.EmvTestUtil.assertSw;
import static emvcardsimulator.EmvTestUtil.hex;
import static emvcardsimulator.EmvTestUtil.send;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import javacard.framework.ISO7816;
import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Fault injection of the payment application with the test card profile, on the contact interface with T=1.
 */
public class FaultInjectionTest {
    private static final byte[] APPLET_AID = hex("AF FF FF FF FF 12 34");
    private static final String SETUP_FILE = "../config/card_setup_app_apdus.yaml";
    private static final String SELECT = "00 A4 04 00 07 AF FF FF FF FF 12 34 00";
    private static final String GET_PROCESSING_OPTIONS = "80 A8 00 00 02 83 00 00";
    // ATC of the test profile, the exact Le works with T=0 as well
    private static final String GET_DATA_ATC = "80 CA 9F 36 05";
    private static final String ATC = "9F 36 02 00 F0";

    /**
     * Transport protocol of the tests.
     */
    protected String protocol() {
        return SmartCard.PROTOCOL_T1;
    }

    @BeforeEach
    public void setup() throws CardException, IOException {
        EmvTestUtil.installAndPersonalize(protocol(), APPLET_AID, PaymentApplicationContainer.class, SETUP_FILE);
        assertSw(0x9000, send(SELECT));
    }

    @AfterEach
    public void disconnect() throws CardException {
        SmartCard.disconnect();
        SmartCard.setLogging(true);
    }

    /**
     * SET FAULT of the table entry: kind || INS || interface || trigger mode || n || kind specific data.
     */
    private static ResponseAPDU setFault(int index, String data) throws CardException {
        int length = hex(data).length;
        return send(String.format("80 11 %02X 00 %02X %s", index, length, data));
    }

    private static void fault(int index, String data) throws CardException {
        assertSw(0x9000, setFault(index, data));
    }

    private static byte[] getDataAtc() throws CardException {
        ResponseAPDU response = send(GET_DATA_ATC);
        assertSw(0x9000, response);
        return response.getData();
    }

    @Test
    public void setFaultTest() throws CardException {
        assertSw(ISO7816.SW_INCORRECT_P1P2, send("80 11 00 01 0B 01 00 00 00 00 9F 36 00 02 02 AA"));
        assertSw(ISO7816.SW_INCORRECT_P1P2, setFault(8, "01 00 00 00 00 9F 36 00 02 02 AA"));
        assertSw(ISO7816.SW_WRONG_LENGTH, setFault(0, "01 00 00 00"));
        assertSw(ISO7816.SW_WRONG_LENGTH, setFault(0, "01 00 00 00 00 9F 36 00 02 02"));
        assertSw(ISO7816.SW_WRONG_LENGTH, setFault(0, "03 00 00 00 00 69 85"));
        // Kind, interface, trigger mode, n of a counting trigger, tag
        assertSw(ISO7816.SW_DATA_INVALID, setFault(0, "06 00 00 00 00 00 00"));
        assertSw(ISO7816.SW_DATA_INVALID, setFault(0, "03 00 03 00 00 69 85 00"));
        assertSw(ISO7816.SW_DATA_INVALID, setFault(0, "03 00 00 04 01 69 85 00"));
        assertSw(ISO7816.SW_DATA_INVALID, setFault(0, "03 00 00 02 00 69 85 00"));
        assertSw(ISO7816.SW_DATA_INVALID, setFault(0, "01 00 00 00 00 00 36 00 02 02 AA"));
        // Kind specific data: value strategy, long form length of 1 - 4 bytes, chain mode, part length of forced chaining
        assertSw(ISO7816.SW_DATA_INVALID, setFault(0, "01 00 00 00 00 9F 36 00 02 05 AA"));
        assertSw(ISO7816.SW_DATA_INVALID, setFault(0, "02 00 00 00 00 9F 36 02 05 00"));
        assertSw(ISO7816.SW_DATA_INVALID, setFault(0, "02 00 00 00 00 9F 36 09 00 00"));
        assertSw(ISO7816.SW_DATA_INVALID, setFault(0, "04 00 00 00 00 06 00"));
        assertSw(ISO7816.SW_DATA_INVALID, setFault(0, "04 00 00 00 00 05 00"));
        assertArrayEquals(hex(ATC), getDataAtc());

        // Fault of a tag that does not exist yet, and clearing the entry
        fault(7, "01 00 00 00 00 DF 81 01 00 02 02 AA");
        fault(7, "");

        assertSw(ISO7816.SW_INCORRECT_P1P2, send("80 07 00 02 00"));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 07 00 01 01 12"));
    }

    @Test
    public void faultResetTest() throws CardException {
        fault(0, "01 00 00 00 00 9F 36 00 02 02 AA");
        assertArrayEquals(hex("9F 36 02 AA AA"), getDataAtc());

        assertSw(0x9000, send("80 07 00 00 00"));
        assertArrayEquals(hex(ATC), getDataAtc());

        fault(0, "01 00 00 00 00 9F 36 00 02 02 AA");
        assertSw(0x9000, send("80 05 00 00 00"));
        assertSw(0x9000, send("80 01 9F 36 02 00 F0"));
        assertArrayEquals(hex(ATC), getDataAtc());
    }

    @Test
    public void tagValueTest() throws CardException {
        // Fill, the value is extended to the range and the length is encoded for the mutated value
        fault(0, "01 00 00 00 00 9F 36 00 02 02 AA");
        assertArrayEquals(hex("9F 36 02 AA AA"), getDataAtc());
        fault(0, "01 00 00 00 00 9F 36 01 03 02 55");
        assertArrayEquals(hex("9F 36 04 00 55 55 55"), getDataAtc());
        // Bytes between the value and the range are zeros
        fault(0, "01 00 00 00 00 9F 36 04 01 02 11");
        assertArrayEquals(hex("9F 36 05 00 F0 00 00 11"), getDataAtc());

        // XOR, argument '00' flips one bit
        fault(0, "01 00 00 00 00 9F 36 00 02 01 FF");
        assertArrayEquals(hex("9F 36 02 FF 0F"), getDataAtc());
        fault(0, "01 00 00 00 00 9F 36 00 02 01 00");
        byte[] data = getDataAtc();
        assertEquals(1, Integer.bitCount(((data[3] & 0xFF) << 8 | (data[4] & 0xFF)) ^ 0x00F0));

        // Boundary values of the firings
        fault(0, "01 00 00 00 00 9F 36 00 02 03 00");
        for (String value : new String[] { "00 00", "01 01", "7F 7F", "80 80", "FE FE", "FF FF", "00 00" }) {
            assertArrayEquals(hex("9F 36 02 " + value), getDataAtc());
        }

        // Increment by the number of firings, with carry
        fault(0, "01 00 00 00 00 9F 36 00 02 04 00");
        assertArrayEquals(hex("9F 36 02 00 F1"), getDataAtc());
        assertArrayEquals(hex("9F 36 02 00 F2"), getDataAtc());
        assertSw(0x9000, send("80 01 9F 36 02 00 FF"));
        assertArrayEquals(hex("9F 36 02 01 02"), getDataAtc());

        // Several faults of the same tag
        assertSw(0x9000, send("80 01 9F 36 02 00 F0"));
        fault(0, "01 00 00 00 00 9F 36 00 01 02 11");
        fault(1, "01 00 00 00 00 9F 36 02 01 02 22");
        assertArrayEquals(hex("9F 36 03 11 F0 22"), getDataAtc());
    }

    @Test
    public void randomValueTest() throws CardException {
        fault(0, "01 00 00 00 00 9F 36 00 10 00 00");
        byte[] first = getDataAtc();
        assertEquals(19, first.length);
        assertArrayEquals(hex("9F 36 10"), Arrays.copyOf(first, 3));
        assertFalse(Arrays.equals(first, getDataAtc()));

        // Same sequence with the same seed
        assertSw(0x9000, send("80 07 00 01 02 12 34"));
        first = getDataAtc();
        byte[] second = getDataAtc();
        assertFalse(Arrays.equals(first, second));
        assertSw(0x9000, send("80 07 00 01 02 12 34"));
        assertArrayEquals(first, getDataAtc());
        assertArrayEquals(second, getDataAtc());
    }

    @Test
    public void tagValueLengthTest() throws CardException {
        // Value is at most 255 bytes, the template of 82 and 94 0C is longer than 255 bytes
        fault(0, "01 00 00 00 00 82 FF FF 02 AA");
        ResponseAPDU response = send(GET_PROCESSING_OPTIONS);
        assertSw(0x9000, response);
        assertEquals(4 + 258 + 14, response.getData().length);
        assertArrayEquals(hex("77 82 01 10 82 81 FF 3C 00 00"), Arrays.copyOf(response.getData(), 10));

        // Response template longer than the response buffer is truncated
        fault(0, "01 00 00 00 00 82 00 FF 02 AA");
        fault(1, "01 00 00 00 00 94 00 FF 02 BB");
        assertSw(0x9000, send(SELECT));
        response = send(GET_PROCESSING_OPTIONS);
        assertSw(0x9000, response);
        assertEquals(512, response.getData().length);
        assertArrayEquals(hex("77 82 01 FC 82 81 FF AA"), Arrays.copyOf(response.getData(), 8));
    }

    @Test
    public void tagEncodingTest() throws CardException {
        String[][] encodings = {
            // Length delta
            { "01 01 00", "9F 36 03 00 F0" },
            { "01 FF 00", "9F 36 01 00 F0" },
            // Long form length
            { "02 01 00", "9F 36 81 02 00 F0" },
            { "02 02 00", "9F 36 82 00 02 00 F0" },
            { "02 04 00", "9F 36 84 00 00 00 02 00 F0" },
            // Indefinite length, with end-of-contents
            { "03 00 00", "9F 36 80 00 F0" },
            { "03 01 00", "9F 36 80 00 F0 00 00" },
            { "04 00 00", "9F" },
            { "05 00 00", "BF 36 02 00 F0" },
            { "06 03 FF", "FF FF FF 9F 36 02 00 F0" },
            { "08 00 00", "9F 36 02 00 F0 9F 36 02 00 F0" },
        };
        for (String[] encoding : encodings) {
            fault(0, "02 00 00 00 00 9F 36 " + encoding[0]);
            assertArrayEquals(hex(encoding[1]), getDataAtc(), encoding[0]);
        }

        // Encoding with a mutated value
        fault(1, "01 00 00 00 00 9F 36 00 03 02 AA");
        fault(0, "02 00 00 00 00 9F 36 01 FE 00");
        assertArrayEquals(hex("9F 36 01 AA AA AA"), getDataAtc());
        fault(1, "");

        // Omitted from the response template
        fault(0, "02 00 00 00 00 94 07 00 00");
        ResponseAPDU response = send(GET_PROCESSING_OPTIONS);
        assertSw(0x9000, response);
        assertArrayEquals(hex("77 04 82 02 3C 00"), response.getData());
    }

    @Test
    public void threeByteTagTest() throws CardException {
        assertSw(0x9000, send("80 01 00 00 05 DF 81 01 AA BB"));
        assertSw(0x9000, send("80 02 00 01 04 82 DF 81 01"));

        fault(0, "01 00 00 00 00 DF 81 01 01 02 02 55");
        ResponseAPDU response = send(GET_PROCESSING_OPTIONS);
        assertSw(0x9000, response);
        assertArrayEquals(hex("77 0B 82 02 3C 00 DF 81 01 03 AA 55 55"), response.getData());
    }

    @Test
    public void recordTest() throws CardException {
        // Record as is
        assertSw(0x9000, send("80 04 05 0C 08 70 06 5A 03 12 34 56 00"));
        fault(0, "01 00 00 00 00 5A 00 01 02 AA");
        ResponseAPDU response = send("00 B2 05 0C 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("70 06 5A 03 AA 34 56 00"), response.getData());

        fault(1, "02 00 00 00 00 70 08 00 00");
        response = send("00 B2 05 0C 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("70 06 5A 03 AA 34 56 00 70 06 5A 03 AA 34 56 00"), response.getData());

        // Record of a tag list
        fault(0, "");
        assertSw(0x9000, send("80 03 06 0C 02 9F 36"));
        fault(1, "02 00 00 00 00 70 06 02 00");
        response = send("00 B2 06 0C 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("00 00 70 05 " + ATC), response.getData());
    }

    @Test
    public void triggerTest() throws CardException {
        final String fill = "9F 36 00 02 02 AA";
        final String filled = "9F 36 02 AA AA";

        // Once on the second GET DATA, setup commands do not count
        fault(0, "01 CA 00 02 02 " + fill);
        assertArrayEquals(hex(ATC), getDataAtc());
        assertSw(0x9000, send("80 01 9F 13 02 00 00"));
        assertArrayEquals(hex(filled), getDataAtc());
        assertArrayEquals(hex(ATC), getDataAtc());
        assertArrayEquals(hex(ATC), getDataAtc());

        // Every second GET DATA
        fault(0, "01 CA 00 03 02 " + fill);
        for (int i = 0; i < 3; i++) {
            assertArrayEquals(hex(ATC), getDataAtc());
            assertArrayEquals(hex(filled), getDataAtc());
        }

        // Other command
        fault(0, "01 B2 00 00 00 " + fill);
        assertArrayEquals(hex(ATC), getDataAtc());

        // Interface
        fault(0, "01 CA 02 00 00 " + fill);
        assertArrayEquals(hex(ATC), getDataAtc());
        fault(0, "01 CA 01 00 00 " + fill);
        assertArrayEquals(hex(filled), getDataAtc());

        // Randomly 1 in 2 with a seed
        assertSw(0x9000, send("80 07 00 01 02 AB CD"));
        fault(0, "01 CA 00 01 02 " + fill);
        int fired = 0;
        for (int i = 0; i < 40; i++) {
            if (Arrays.equals(hex(filled), getDataAtc())) {
                fired++;
            }
        }
        assertTrue(fired > 0 && fired < 40, "fired " + fired);
    }

    @Test
    public void statusWordTest() throws CardException {
        // Command is not processed
        fault(0, "03 A8 00 00 00 6A 81 00");
        ResponseAPDU response = send(GET_PROCESSING_OPTIONS);
        assertSw(0x6A81, response);
        assertEquals(0, response.getData().length);
        // ATC is incremented by GET PROCESSING OPTIONS
        assertArrayEquals(hex(ATC), getDataAtc());

        fault(0, "03 A8 00 00 00 90 00 00");
        response = send(GET_PROCESSING_OPTIONS);
        assertSw(0x9000, response);
        assertEquals(0, response.getData().length);

        // Command is processed and its response data is sent
        fault(0, "03 CA 00 00 00 62 83 01");
        response = send(GET_DATA_ATC);
        assertSw(0x6283, response);
        assertArrayEquals(hex(ATC), response.getData());

        fault(0, "03 A8 00 00 00 62 83 01");
        response = send(GET_PROCESSING_OPTIONS);
        assertSw(0x6283, response);
        assertArrayEquals(hex("77 12 82 02 3C 00 94 0C"), Arrays.copyOf(response.getData(), 8));

        // Error of the command is replaced
        fault(0, "03 A8 00 00 00 90 00 01");
        assertSw(0x9000, send(GET_PROCESSING_OPTIONS));
    }

    @Test
    public void statusWordLogTest() throws CardException {
        assertSw(0x9000, send("80 06 01 00 00"));
        fault(0, "03 CA 00 00 00 62 83 01");
        fault(1, "03 B2 00 00 00 90 00 01");
        assertSw(0x6283, send(GET_DATA_ATC));
        assertSw(0x9000, send("00 B2 09 0C 00"));

        String[] expectedLog = {
            GET_DATA_ATC,
            ATC,
            "62 83",
            "00 B2 09 0C 00",
        };
        for (String expected : expectedLog) {
            ResponseAPDU response = send("80 06 00 00 00");
            assertSw(0x9000, response);
            assertArrayEquals(hex(expected), response.getData());
        }
        assertSw(ISO7816.SW_RECORD_NOT_FOUND, send("80 06 00 00 00"));
    }

    @Test
    public void responseChainTest() throws CardException {
        // Response in parts of four bytes
        fault(0, "04 CA 00 00 00 05 04");
        ResponseAPDU response = SmartCard.transmitCommand(hex(GET_DATA_ATC));
        assertSw(0x6101, response);
        assertArrayEquals(hex("9F 36 02 00"), response.getData());
        response = SmartCard.transmitCommand(hex("00 C0 00 00 01"));
        assertSw(0x9000, response);
        assertArrayEquals(hex("F0"), response.getData());
        assertArrayEquals(hex(ATC), getDataAtc());

        // Same part again
        fault(1, "04 CA 00 00 00 01 00");
        response = SmartCard.transmitCommand(hex(GET_DATA_ATC));
        for (int i = 0; i < 3; i++) {
            assertSw(0x6104, response);
            assertArrayEquals(hex("9F 36 02 00"), response.getData());
            response = SmartCard.transmitCommand(hex("00 C0 00 00 04"));
        }

        // Wrong remaining length
        fault(1, "04 CA 00 00 00 02 10");
        response = SmartCard.transmitCommand(hex(GET_DATA_ATC));
        assertSw(0x6110, response);
        assertArrayEquals(hex("9F 36 02 00"), response.getData());
        fault(0, "");
        fault(1, "");

        // Wrong exact length
        fault(0, "04 CA 00 00 00 03 03");
        assertSw(0x6C03, SmartCard.transmitCommand(hex("80 CA 9F 36 02")));

        // Truncated response
        fault(0, "04 CA 00 00 00 04 02");
        response = SmartCard.transmitCommand(hex(GET_DATA_ATC));
        assertSw(0x9000, response);
        assertArrayEquals(hex("9F 36 02"), response.getData());
    }

    @Test
    public void delayTest() throws CardException {
        fault(0, "05 CA 00 00 00 01 00");
        assertArrayEquals(hex(ATC), getDataAtc());
    }
}
