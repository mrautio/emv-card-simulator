package emvcardsimulator;

import static emvcardsimulator.EmvTestUtil.assertSw;
import static emvcardsimulator.EmvTestUtil.hex;
import static emvcardsimulator.EmvTestUtil.send;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import javacard.framework.ISO7816;
import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;

/**
 * EMV protocol behaviour of the payment application on the contact interface with T=0: the tests of
 * PaymentApplicationProtocolTest and the T=0 exchanges of EMV Book 1, Annex A.
 */
public class PaymentApplicationProtocolT0Test extends PaymentApplicationProtocolTest {
    private static final String GET_PROCESSING_OPTIONS = "80 A8 00 00 02 83 00 00";
    // GET PROCESSING OPTIONS response of the test profile, template 2 with AIP and AFL
    private static final int GET_PROCESSING_OPTIONS_RESPONSE_LENGTH = 0x14;

    @Override
    protected String protocol() {
        return SmartCard.PROTOCOL_T0;
    }

    /**
     * Case 4 command: the card returns '61xx' without data and the terminal gets the data with GET RESPONSE (EMV Book 1, A4).
     */
    @Test
    public void caseFourCommandTest() throws CardException {
        ResponseAPDU response = SmartCard.transmitCommand(hex(GET_PROCESSING_OPTIONS));
        assertSw(0x6100 | GET_PROCESSING_OPTIONS_RESPONSE_LENGTH, response);
        assertEquals(0, response.getData().length);

        response = SmartCard.transmitCommand(hex(String.format("00 C0 00 00 %02X", GET_PROCESSING_OPTIONS_RESPONSE_LENGTH)));
        assertSw(0x9000, response);
        assertEquals(GET_PROCESSING_OPTIONS_RESPONSE_LENGTH, response.getData().length);
        assertArrayEquals(hex("77 12 82 02 3C 00 94 0C"), Arrays.copyOfRange(response.getData(), 0, 8));

        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, SmartCard.transmitCommand(hex("00 C0 00 00 00")));
    }

    /**
     * SELECT returns the FCI with GET RESPONSE.
     */
    @Test
    public void selectTest() throws CardException {
        ResponseAPDU response = SmartCard.transmitCommand(hex("00 A4 04 00 07 AF FF FF FF FF 12 34 00"));
        assertEquals(0x61, response.getSW1());
        assertEquals(0, response.getData().length);

        response = send("00 A4 04 00 07 AF FF FF FF FF 12 34 00");
        assertSw(0x9000, response);
        assertEquals((byte) 0x6F, response.getData()[0]);
    }

    /**
     * GET RESPONSE with P3 longer than the remaining data is answered with '6Cxx'.
     */
    @Test
    public void getResponseWrongLengthTest() throws CardException {
        assertSw(0x6100 | GET_PROCESSING_OPTIONS_RESPONSE_LENGTH, SmartCard.transmitCommand(hex(GET_PROCESSING_OPTIONS)));

        assertSw(0x6C00 | GET_PROCESSING_OPTIONS_RESPONSE_LENGTH, SmartCard.transmitCommand(hex("00 C0 00 00 00")));
        assertSw(0x6C00 | GET_PROCESSING_OPTIONS_RESPONSE_LENGTH,
            SmartCard.transmitCommand(hex(String.format("00 C0 00 00 %02X", GET_PROCESSING_OPTIONS_RESPONSE_LENGTH + 1))));

        // Shorter P3 returns a part of the data
        ResponseAPDU response = SmartCard.transmitCommand(hex("00 C0 00 00 04"));
        assertSw(0x6100 | (GET_PROCESSING_OPTIONS_RESPONSE_LENGTH - 4), response);
        assertArrayEquals(hex("77 12 82 02"), response.getData());

        response = SmartCard.transmitCommand(hex(String.format("00 C0 00 00 %02X", GET_PROCESSING_OPTIONS_RESPONSE_LENGTH - 4)));
        assertSw(0x9000, response);
        assertArrayEquals(hex("3C 00 94 0C"), Arrays.copyOfRange(response.getData(), 0, 4));
    }

    /**
     * Case 2 command: P3 is the exact response length, P3 '00' (256 bytes) or another length is answered with '6Cxx'
     * and the terminal sends the command again with P3 xx (EMV Book 1, A2).
     */
    @Test
    public void caseTwoCommandTest() throws CardException {
        assertSw(0x6C05, SmartCard.transmitCommand(hex("80 CA 9F 36 00")));
        ResponseAPDU response = SmartCard.transmitCommand(hex("80 CA 9F 36 05"));
        assertSw(0x9000, response);
        assertArrayEquals(hex("9F 36 02 00 F0"), response.getData());

        response = SmartCard.transmitCommand(hex("00 B2 01 14 00"));
        assertEquals(0x6C, response.getSW1());
        int length = response.getSW2();
        response = SmartCard.transmitCommand(hex(String.format("00 B2 01 14 %02X", length)));
        assertSw(0x9000, response);
        assertEquals(length, response.getData().length);

        assertSw(0x6C08, SmartCard.transmitCommand(hex("00 84 00 00 00")));
        assertEquals(8, send("00 84 00 00 00").getData().length);
    }
}
