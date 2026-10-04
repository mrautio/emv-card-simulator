package emvcardsimulator;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import javacard.framework.AID;
import javacard.framework.Applet;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminals.State;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * SmartCard interface simulator. Helper utility for unit testing.
 */
public class SmartCard {
    // Transport protocols of jcardsim, the protocol of the contact interface is negotiated after the ATR (ISO/IEC 7816-3)
    public static final String PROTOCOL_T0 = "T=0";
    public static final String PROTOCOL_T1 = "T=1";
    // Contactless interface, ISO/IEC 14443-4 type A
    public static final String PROTOCOL_CONTACTLESS = "T=CL,TYPE_A,T1";

    private static CardSimulator cardSimulator;

    private static Card card;

    private static boolean logging = true;

    private static String toHexString(byte[] buf, int offset, int length) {
        if (length == 0) {
            return "[]";
        }

        String result = "[";
        for (int i = offset; i < offset + length - 1; i++) {
            result += String.format("%02X, ", buf[i]);
        }
        result += String.format("%02X]", buf[offset + length - 1]);

        return result;
    }

    /**
     * Enable or disable logging.
     */
    public static void setLogging(boolean logging) {
        SmartCard.logging = logging;
    }

    /**
     * Send APDU command data.
     * @throws CardException
     */
    public static ResponseAPDU transmitCommand(byte[] data) throws CardException {
        return transmitCommand(new CommandAPDU(data));
    }

    /**
     * Send APDU command data.
     * @throws CardException
     */
    public static ResponseAPDU transmitCommand(CommandAPDU data) throws CardException {
        if (logging) {
            System.out.println("REQUEST : " + data + " = " + SmartCard.toHexString(data.getBytes(), 0, data.getBytes().length));
        }

        ResponseAPDU response = cardSimulator.transmitCommand(data);

        if (logging) {
            System.out.println("RESPONSE: " + response + " = " + SmartCard.toHexString(response.getBytes(), 0, response.getBytes().length));
        }

        return response;
    }

    /**
     * Initialize simulator for test suite, the transport protocol is T=0.
     * @throws CardException
     */
    public static void connect() throws CardException {
        connect(PROTOCOL_T0);
    }

    /**
     * Initialize simulator for test suite with the transport protocol.
     * @throws CardException
     */
    public static void connect(String protocol) throws CardException {
        cardSimulator = new CardSimulator();
        cardSimulator.changeProtocol(protocol);
    }

    /**
     * Change the transport protocol, e.g. from the contact to the contactless interface, the applets keep their data.
     */
    public static void changeProtocol(String protocol) {
        cardSimulator.changeProtocol(protocol);
    }

    /**
     * True if the transport protocol is T=0.
     */
    public static boolean isProtocolT0() {
        return PROTOCOL_T0.equals(cardSimulator.getProtocol());
    }

    /**
     * Install an applet.
     * @throws CardException
     */
    public static void install(byte[] aid, Class<? extends Applet> applet) throws CardException {
        cardSimulator.installApplet(new AID(aid, (short) 0, (byte) aid.length), applet);
    }

    /**
     * Disconnect and clean state.
     * @throws CardException
     */
    public static void disconnect() throws CardException {
        if (card != null) {            
            card.endExclusive();
            card.disconnect(true);
        }

        card = null;
        cardSimulator = null;
    }
}
