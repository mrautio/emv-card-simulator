package emvcardsimulator;

import javacard.framework.JCSystem;

/**
 * Personalized data of an applet instance: EMV tags, records and faults. Each applet instance has its own store, e.g. the
 * applications of a multi-application card and the (P)PSE, EmvApplet.process selects the store of the processing applet.
 */
public class DataStore {
    // Store of the applet processing the current command
    static DataStore current;

    EmvTag tagHead;
    EmvTag tagTail;
    ReadRecord recordHead;
    ReadRecord recordTail;

    // Interface of the personalized tags and templates, see EmvTag.SCOPE_*
    byte scope;

    Fault[] faults;
    // Faults triggered by the current command and their random nonces, see Fault.evaluate
    boolean[] activeFaults;
    short[] faultNonces;

    DataStore() {
        faults = new Fault[Fault.TABLE_SIZE];
        for (short i = (short) 0; i < Fault.TABLE_SIZE; i++) {
            faults[i] = new Fault();
        }
        activeFaults = JCSystem.makeTransientBooleanArray(Fault.TABLE_SIZE, JCSystem.CLEAR_ON_DESELECT);
        faultNonces = JCSystem.makeTransientShortArray(Fault.TABLE_SIZE, JCSystem.CLEAR_ON_DESELECT);
    }
}
