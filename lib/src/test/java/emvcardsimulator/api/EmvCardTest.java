package emvcardsimulator.api;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

public class EmvCardTest {

    private static final byte[] SW_NO_ERROR = {(byte) 0x90, 0x00};
    private static final String SELECT_APP = "00 A4 04 00 07 AF FF FF FF FF 12 34 00";
    // CDOL1 data: amounts, country, TVR, currency, date, type and unpredictable number
    private static final String CDOL1_DATA = "00 00 00 00 01 00 00 00 00 00 00 00 02 46 00 00 00 00 00 09 78 26 10 04 00 12 34 56 78";

    private static byte[] hex(String hex) throws ScriptException {
        return ApduScript.parse("- req: '" + hex + "'\n  res: ''").commands().get(0).request;
    }

    private static EmvCard card(String... scripts) throws Exception {
        EmvCard card = new EmvCard(EmvCard.PROTOCOL_CONTACTLESS);
        for (String script : scripts) {
            card.personalize(ApduScript.bundled(script));
        }
        card.reset();
        return card;
    }

    // Response data of '61xx' is completed with GET RESPONSE, like a terminal does
    private static byte[] transmitOk(EmvCard card, String command) throws ScriptException {
        byte[] response = card.transmit(hex(command));
        while (response.length >= 2 && response[response.length - 2] == (byte) 0x61) {
            byte[] next = card.transmit(new byte[] {0x00, (byte) 0xC0, 0x00, 0x00, response[response.length - 1]});
            byte[] data = Arrays.copyOf(response, response.length - 2 + next.length);
            System.arraycopy(next, 0, data, response.length - 2, next.length);
            response = data;
        }
        assertArrayEquals(SW_NO_ERROR, Arrays.copyOfRange(response, response.length - 2, response.length), command);
        return response;
    }

    private static String selectPpse() {
        return "00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00";
    }

    private static void assertPpseLists(EmvCard card, String aid) throws ScriptException {
        byte[] fci = transmitOk(card, selectPpse());
        assertEquals((byte) 0x6F, fci[0]);
        assertTrue(new String(fci, StandardCharsets.ISO_8859_1).contains(new String(hex(aid), StandardCharsets.ISO_8859_1)));
    }

    @Test
    public void bundledScriptsParse() throws Exception {
        for (String name : ApduScript.BUNDLED) {
            assertTrue(ApduScript.bundled(name).commands().size() > 0, name);
        }
    }

    @Test
    public void contactlessTransaction() throws Exception {
        EmvCard card = card("card_setup_pse_apdus.yaml", "card_setup_app_apdus.yaml", "card_setup_ppse_apdus.yaml");
        assertEquals(3, card.aids().size());

        assertPpseLists(card, "AF FF FF FF FF 12 34");
        assertEquals((byte) 0x6F, transmitOk(card, SELECT_APP)[0]);
        assertEquals((byte) 0x77, transmitOk(card, "80 A8 00 00 02 83 00 00")[0]);
        assertEquals((byte) 0x70, transmitOk(card, "00 B2 01 1C 00")[0]);
        assertEquals((byte) 0x77, transmitOk(card, "80 AE 80 00 1D " + CDOL1_DATA + " 00")[0]);
    }

    @Test
    public void visaContactless() throws Exception {
        EmvCard card = card("test/card_setup_ppse_apdus.yaml", "test/card_setup_app_apdus.yaml",
            "test/card_setup_app_visa_contactless_apdus.yaml");

        assertPpseLists(card, "AF FF FF FF FF 12 34");
        transmitOk(card, SELECT_APP);
        // PDOL: Terminal Transaction Qualifiers and CDOL1 data, qVSDC returns the cryptogram in the response
        assertEquals((byte) 0x77, transmitOk(card, "80 A8 00 00 23 83 21 36 00 40 00 " + CDOL1_DATA + " 00")[0]);
    }

    @Test
    public void mastercardContactless() throws Exception {
        assertPpseLists(card("test/card_setup_ppse_mastercard_apdus.yaml", "test/card_setup_app_apdus.yaml",
            "test/card_setup_app_mastercard_contactless_apdus.yaml"), "AF FF FF FF FF 12 34");
        assertPpseLists(card("test/card_setup_ppse_mockstercard_apdus.yaml", "test/card_setup_app_apdus.yaml",
            "test/card_setup_app_mastercard_contactless_apdus.yaml", "test/card_setup_app_mockstercard_contactless_apdus.yaml"),
            "AF FF FF FF FF 12 34");
    }

    @Test
    public void spankkiFuzzing() throws Exception {
        EmvCard card = card("card_setup_app_apdus-spankki.yaml", "card_setup_ppse_apdus-spankki.yaml", "setup_fuzzing_apdus.yaml");

        assertPpseLists(card, "A0 00 00 00 03 10 10 01");
        transmitOk(card, "00 A4 04 00 08 A0 00 00 00 03 10 10 01 00");
    }

    @Test
    public void emvTags() throws Exception {
        assertArrayEquals(hex("12 34 56 00 12 34 56 08"), ApduScript.bundled("card_setup_app_apdus.yaml").emvTags().get(0x5A));
    }

    @Test
    public void unexpectedResponseFails() throws Exception {
        ApduScript script = ApduScript.parse("- req: '00 A4 04 00 07 AF FF FF FF FF 12 34'\n  res: '6A 82' # comment\n");
        assertThrows(ScriptException.class, () -> new EmvCard(EmvCard.PROTOCOL_CONTACTLESS).personalize(script));
    }

    @Test
    public void invalidSyntaxFails() {
        assertThrows(ScriptException.class, () -> ApduScript.parse("- req: [0x00]\n  res: '90 00'"));
        assertThrows(ScriptException.class, () -> ApduScript.parse("- req: '00 A4 0'\n  res: '90 00'"));
        assertThrows(ScriptException.class, () -> ApduScript.parse("- req: '00 A4 04 00'"));
    }
}
