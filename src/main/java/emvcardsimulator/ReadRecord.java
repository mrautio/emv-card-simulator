package emvcardsimulator;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class ReadRecord extends TagTemplate {

    protected ReadRecord next;
    protected ReadRecord previous;

    private byte[] record;
    // Record data is the record as is, not a tag list
    private boolean raw;

    protected ReadRecord(short recordId, byte[] src, short srcOffset, byte length) {
        record = new byte[2];

        Util.setShort(record, (short) 0, recordId);

        if (length != 0) {
            setData(src, srcOffset, length);
        }

        DataStore store = DataStore.current;
        next = null;
        previous = store.recordTail;
        if (previous != null) {
            previous.next = this;
        }

        if (store.recordHead == null) {
            store.recordHead = this;
        }
        store.recordTail = this;
    }

    /**
     * Add or update READ RECORD TLV tag list.
     */
    public static ReadRecord setRecord(short recordId, byte[] src, short srcOffset, byte length) {
        return setRecord(recordId, src, srcOffset, length, false);
    }

    /**
     * Add or update READ RECORD TLV tag list, or the record as is when raw.
     */
    public static ReadRecord setRecord(short recordId, byte[] src, short srcOffset, byte length, boolean raw) {
        ReadRecord readRecord = ReadRecord.findRecord(recordId);
        if (readRecord == null) {
            readRecord = new ReadRecord(recordId, src, srcOffset, length);
        } else {
            readRecord.setData(src, srcOffset, length);
        }
        readRecord.raw = raw;

        return readRecord;
    }

    /**
     * True if the record data is the record as is, e.g. a record template '70' of a personalization data grouping.
     */
    public boolean isRaw() {
        return raw;
    }

    /**
     * Find record.
     */
    public static ReadRecord findRecord(short record) {
        for (ReadRecord iter = DataStore.current.recordHead; iter != null; iter = iter.next) {
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

        for (ReadRecord iter = DataStore.current.recordHead; iter != null; ) {
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

        DataStore store = DataStore.current;

        JCSystem.beginTransaction();

        if (store.recordHead == record) {
            store.recordHead = nextRecord;
        }
        if (store.recordTail == record) {
            store.recordTail = previousRecord;
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
        return DataStore.current.recordHead;
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
