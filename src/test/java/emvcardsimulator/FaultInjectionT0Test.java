package emvcardsimulator;

/**
 * Tests of FaultInjectionTest on the contact interface with T=0.
 */
public class FaultInjectionT0Test extends FaultInjectionTest {
    @Override
    protected String protocol() {
        return SmartCard.PROTOCOL_T0;
    }
}
