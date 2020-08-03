package emvcardsimulator;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class ReadRecord extends TagTemplate {

    protected ReadRecord next;
    protected ReadRecord previous;
    private static ReadRecord head = null;
    private static ReadRecord tail = null;

    private byte[] record;

    protected ReadRecord(short recordId, byte[] src, short srcOffset, byte length) {
        record = new byte[2];

        Util.setShort(record, (short) 0, recordId);

        if (length != 0) {
            setData(src, srcOffset, length);
        }

        next = null;
        previous = tail;
        if (previous != null) {
            previous.next = this;
        }

        if (head == null) {
            head = this;
        }
        tail = this;
    }

    /**
     * Add or update READ RECORD TLV tag list.
     */
    public static ReadRecord setRecord(short recordId, byte[] src, short srcOffset, byte length) {
        ReadRecord readRecord = ReadRecord.findRecord(recordId);
        if (readRecord == null) {
            readRecord = new ReadRecord(recordId, src, srcOffset, length);
        } else {
            readRecord.setData(src, srcOffset, length);
        }

        return readRecord;
    }

    /**
     * Find record.
     */
    public static ReadRecord findRecord(short record) {
        for (ReadRecord iter = ReadRecord.head; iter != null; iter = iter.next) {
            short iterRecord = Util.getShort(iter.record, (short) 0);
            if (record == iterRecord) {
                return iter;
            }
        }

        return null;
    }

    /**
     * Remove all stored records.
     */
    public static short clear() {
        short count = (short) 0;

        for (ReadRecord iter = ReadRecord.head; iter != null; ) {
            short iterRecord = Util.getShort(iter.record, (short) 0);

            iter = iter.next;

            if (removeRecord(iterRecord)) {
                count++;
            }
        }    

        if (JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }

        return count;
    }

    /**
     * Remove record.
     */
    public static boolean removeRecord(short recordId) {
        ReadRecord record = findRecord(recordId);
        if (record == null) {
            return false;
        }

        ReadRecord previousRecord = record.previous;
        ReadRecord nextRecord = record.next;

        JCSystem.beginTransaction();

        if (head == record) {
            head = nextRecord;
        }
        if (tail == record) {
            tail = previousRecord;
        }
        if (previousRecord != null) {
            previousRecord.next = nextRecord;
        }
        if (nextRecord != null) {
            nextRecord.previous = previousRecord;
        }

        JCSystem.commitTransaction();

        return true;
    }

    /**
     * Get first READ RECORD entry.
     */
    public static ReadRecord getHead() {
        return ReadRecord.head;
    }

    /**
     * Get next READ RECORD entry.
     */
    public ReadRecord getNext() {
        return next;
    }

    /**
     * Get first READ RECORD id.
     */
    public byte[] getRecord() {
        return record;
    }
}
