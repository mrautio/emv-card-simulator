package emvcardsimulator.api;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.base.SimulatorRuntime;

import emvcardsimulator.PaymentApplication;
import emvcardsimulator.PaymentSystemEnvironment;
import emvcardsimulator.ProximityPaymentSystemEnvironment;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javacard.framework.AID;
import javacard.framework.Applet;

/**
 * Simulated EMV card running the emvcardsimulator applets.
 *
 * <p>Applets are installed when a personalization script selects them: {@code 1PAY.SYS.DDF01} as
 * {@link PaymentSystemEnvironment}, {@code 2PAY.SYS.DDF01} as {@link ProximityPaymentSystemEnvironment} and other AIDs as
 * {@link PaymentApplication}. Card wide applet state, e.g. blocked card and APDU log, is in static fields, so use one card
 * at a time.
 */
public final class EmvCard {

    public static final byte[] PSE_AID = "1PAY.SYS.DDF01".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] PPSE_AID = "2PAY.SYS.DDF01".getBytes(StandardCharsets.US_ASCII);

    // jCardSim transport protocols
    public static final String PROTOCOL_T0 = "T=0";
    public static final String PROTOCOL_T1 = "T=1";
    public static final String PROTOCOL_CONTACTLESS = "T=CL,TYPE_A,T1";

    private static final byte[] SW_NO_ERROR = {(byte) 0x90, 0x00};

    private final Simulator simulator = new Simulator(new SimulatorRuntime());
    private final List<byte[]> aids = new ArrayList<>();

    /**
     * Create a card on the interface of the transport protocol, e.g. {@link #PROTOCOL_CONTACTLESS}.
     */
    public EmvCard(String protocol) {
        simulator.changeProtocol(protocol);
    }

    /**
     * Run the script against the card, installing applets on their first SELECT. With T=0 a '61xx' status, response data
     * available with GET RESPONSE, is expected as '9000'.
     */
    public synchronized void personalize(ApduScript script) throws ScriptException {
        int index = 0;
        for (ApduScript.Command command : script.commands()) {
            index++;
            byte[] aid = selectedAid(command.request);
            if (aid != null && !isInstalled(aid)) {
                install(aid);
            }

            byte[] response = transmit(command.request);
            byte[] statusWord = Arrays.copyOfRange(response, Math.max(0, response.length - 2), response.length);
            if (statusWord.length == 2 && statusWord[0] == (byte) 0x61) {
                statusWord = SW_NO_ERROR;
            }
            if (!Arrays.equals(statusWord, command.response)) {
                throw new ScriptException(String.format("Command %d %s: expected %s, got %s",
                    index, hex(command.request), hex(command.response), hex(statusWord)));
            }
        }
    }

    public synchronized byte[] transmit(byte[] command) {
        return simulator.transmitCommand(command);
    }

    /**
     * Power cycle the card, e.g. when the card leaves the reader field. Personalization is kept.
     */
    public synchronized void reset() {
        simulator.reset();
    }

    /**
     * AIDs of the installed applets.
     */
    public synchronized List<byte[]> aids() {
        List<byte[]> result = new ArrayList<>();
        for (byte[] aid : aids) {
            result.add(aid.clone());
        }
        return result;
    }

    private boolean isInstalled(byte[] aid) {
        for (byte[] installed : aids) {
            if (Arrays.equals(installed, aid)) {
                return true;
            }
        }
        return false;
    }

    private void install(byte[] aid) {
        Class<? extends Applet> applet = Arrays.equals(aid, PSE_AID) ? PaymentSystemEnvironment.class
            : Arrays.equals(aid, PPSE_AID) ? ProximityPaymentSystemEnvironment.class
            : PaymentApplication.class;
        simulator.installApplet(new AID(aid, (short) 0, (byte) aid.length), applet);
        aids.add(aid.clone());
    }

    private static byte[] selectedAid(byte[] command) {
        boolean selectByName = command.length > 5 && command[0] == 0x00 && command[1] == (byte) 0xA4 && command[2] == 0x04;
        int length = selectByName ? command[4] & 0xFF : 0;
        return selectByName && command.length >= 5 + length ? Arrays.copyOfRange(command, 5, 5 + length) : null;
    }

    private static String hex(byte[] data) {
        StringBuilder result = new StringBuilder();
        for (byte b : data) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
}
