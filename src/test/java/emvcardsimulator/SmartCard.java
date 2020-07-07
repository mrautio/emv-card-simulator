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

    private static HashMap<String, AID> installedApplets;

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
        installedApplets = new HashMap<>();
    }

    /**
     * Install an applet.
     * @throws CardException
     */
    public static void install(String aid, Class<? extends Applet> applet) throws CardException {
        AID appletAid = AIDUtil.create(aid);
        cardSimulator.installApplet(appletAid, applet);
        installedApplets.put(aid, appletAid);
    }

    /**
     * Select an applet.
     * @throws CardException
     */
    public static ResponseAPDU select(String aid) throws CardException {
        if (!installedApplets.containsKey(aid)) {
            throw new CardException("Applet has not been installed! aid:" + aid);
        }

        //cardSimulator.selectApplet(installedApplets.get(aid));
        ResponseAPDU response = transmitCommand(AIDUtil.select(aid));

        return response;
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
        installedApplets = null;
        cardSimulator = null;
    }
}
