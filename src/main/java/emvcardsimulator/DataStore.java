package emvcardsimulator;

/**
 * Personalized data of an applet instance: EMV tags and records. Each applet instance has its own store, e.g. the applications of
 * a multi-application card and the (P)PSE, EmvApplet.process selects the store of the processing applet.
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
}
