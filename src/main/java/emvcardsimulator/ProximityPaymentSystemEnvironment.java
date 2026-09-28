package emvcardsimulator;

import javacard.framework.APDU;

/**
 * Proximity Payment System Environment 2PAY.SYS.DDF01 (EMV Contactless Book B, 3.3).
 * The FCI of the PPSE lists the contactless applications in Directory Entries (tag 61) of the FCI Issuer Discretionary Data (tag BF0C),
 * e.g. ADF Name (4F), Application Label (50), Application Priority Indicator (87) and Kernel Identifier (9F2A). PPSE has no records.
 */
public class ProximityPaymentSystemEnvironment extends PaymentSystemEnvironment {

    public static void install(byte[] buffer, short offset, byte length) {
        (new ProximityPaymentSystemEnvironment()).register();
    }

    public ProximityPaymentSystemEnvironment() {
        super();
    }

    protected void processCommand(APDU apdu, byte[] buf, short cmd, short dataLength) {
        commandNotSupported(cmd);
    }
}
