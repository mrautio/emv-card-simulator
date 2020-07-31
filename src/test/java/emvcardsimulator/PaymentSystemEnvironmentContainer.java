package emvcardsimulator;

import javacard.framework.APDU;
import javacard.framework.ISOException;

/**
 * Unit testing applet abstraction container to catch and print any possible exceptions. 
 */
public class PaymentSystemEnvironmentContainer extends PaymentSystemEnvironment {
    public static void install(byte[] buffer, short offset, byte length) {
        (new PaymentSystemEnvironmentContainer()).register();
    }

    /**
     * Process applet and print stack traces if any.
     */
    @Override
    public void process(APDU apdu) {
        try {
            super.process(apdu);
        } catch (ISOException e) {
            throw e;
        } catch (Exception e) {
            // JCardSim catches all exceptions and omits any possible traces, so print stack trace before throwing
            e.printStackTrace();
            throw e;
        }
    }
}
