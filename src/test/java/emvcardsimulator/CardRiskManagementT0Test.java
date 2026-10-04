package emvcardsimulator;

/**
 * Tests of CardRiskManagementTest on the contact interface with T=0.
 */
public class CardRiskManagementT0Test extends CardRiskManagementTest {
    @Override
    protected String protocol() {
        return SmartCard.PROTOCOL_T0;
    }
}
