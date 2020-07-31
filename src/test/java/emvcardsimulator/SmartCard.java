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

    private static CardSimulator cardSimulator;

    private static Card card;

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
        return cardSimulator.transmitCommand(data);
    }

    /**
     * Initialize simulator for test suite.
     * @throws CardException
     */
    public static void connect() throws CardException {
        cardSimulator = new CardSimulator();
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
