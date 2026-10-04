package emvcardsimulator;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class EmvTag {

    // Interface where a tag is available: both interfaces, or only the contact or the contactless interface. An interface
    // specific tag takes precedence over a tag of both interfaces, e.g. contactless FCI or GET PROCESSING OPTIONS response data.
    public static final byte SCOPE_ANY = (byte) 0x00;
    public static final byte SCOPE_CONTACT = (byte) 0x01;
    public static final byte SCOPE_CONTACTLESS = (byte) 0x02;

    // Interface of the command being processed, set by EmvApplet.process
    static boolean contactless = false;

    protected EmvTag next;
    protected EmvTag previous;

    // Scratch for tag identifiers in right aligned three byte form
    private static byte[] tagIdBuffer = { (byte) 0x00, (byte) 0x00, (byte) 0x00 };
    // Scratch for a tag entry of a one or two byte tag
    private static byte[] tagEntryBuffer = { (byte) 0x00, (byte) 0x00 };

    private byte[] tag;
    private byte[] data;
    private byte   length;
    private byte   scope;

    public byte fuzzOffset      = (byte) 0x00;
    public byte fuzzLength      = (byte) 0x00;
    public byte fuzzFlags       = (byte) 0x00;
    public byte fuzzOccurrence  = (byte) 0x00;

    // Tag is stored right aligned in three bytes, e.g. '00 00 82', '00 9F 36' or 'DF 81 01'
    private static final short TAG_SIZE = (short) 3;

    protected EmvTag(byte scope, byte[] normalizedTag, byte[] src, short srcOffset, byte length) {
        tag = new byte[TAG_SIZE];
        data = new byte[255];
        this.length = length;
        this.scope = scope;

        Util.arrayCopy(normalizedTag, (short) 0, tag, (short) 0, TAG_SIZE);
        if (this.length != 0) {
            setData(src, srcOffset, this.length);
        }

        DataStore store = DataStore.current;
        next = null;
        previous = store.tagTail;
        if (previous != null) {
            previous.next = this;
        }

        if (store.tagHead == null) {
            store.tagHead = this;
        }
        store.tagTail = this;
    }

    /**
     * True if the tag is available on the interface of the current command.
     */
    private boolean isVisible() {
        return scope == SCOPE_ANY || (scope == SCOPE_CONTACTLESS) == contactless;
    }

    /**
     * Length of a tag entry in a tag list: BER-TLV tag of one to three bytes, or '00' followed by a one byte tag.
     */
    public static short tagEntryLength(byte[] buf, short offset) {
        if (buf[offset] == (byte) 0x00) {
            return (short) 2;
        }

        if ((buf[offset] & (byte) 0x1F) != (byte) 0x1F) {
            return (short) 1;
        }

        short length = (short) 2;
        while ((buf[(short) (offset + length - 1)] & (byte) 0x80) != 0) {
            length++;
            if (length > TAG_SIZE) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
        }

        return length;
    }

    /**
     * Copy tag entry to right aligned three byte form.
     */
    private static void normalizeTag(byte[] buf, short offset, byte[] dst) {
        short length = tagEntryLength(buf, offset);
        Util.arrayFillNonAtomic(dst, (short) 0, TAG_SIZE, (byte) 0x00);
        Util.arrayCopyNonAtomic(buf, offset, dst, (short) (TAG_SIZE - length), length);
    }

    /**
     * True if tag entry equals this tag.
     */
    private boolean matches(byte[] buf, short offset) {
        short length = tagEntryLength(buf, offset);
        for (short i = (short) 0; i < (short) (TAG_SIZE - length); i++) {
            if (tag[i] != (byte) 0x00) {
                return false;
            }
        }
        return Util.arrayCompare(buf, offset, tag, (short) (TAG_SIZE - length), length) == (byte) 0x00;
    }

    /**
     * Add or update BER-TLV EMV tag to memory. The tag available on the current interface is updated, a new tag is available on both interfaces.
     */
    public static EmvTag setTag(short tagId, byte[] src, short srcOffset, byte length) {
        EmvTag tag = EmvTag.findTag(tagId);
        if (tag == null) {
            tagIdBuffer[0] = (byte) 0x00;
            Util.setShort(tagIdBuffer, (short) 1, tagId);
            tag = new EmvTag(SCOPE_ANY, tagIdBuffer, src, srcOffset, length);
        } else {
            tag.setData(src, srcOffset, length);
        }

        return tag;
    }

    /**
     * Add or update BER-TLV EMV tag of the interface scope, tag is given as a tag entry, see tagEntryLength.
     */
    public static EmvTag setTag(byte scope, byte[] tagBuf, short tagOffset, byte[] src, short srcOffset, byte length) {
        EmvTag tag = null;
        for (EmvTag iter = DataStore.current.tagHead; iter != null; iter = iter.next) {
            if (iter.scope == scope && iter.matches(tagBuf, tagOffset)) {
                tag = iter;
                break;
            }
        }

        if (tag == null) {
            normalizeTag(tagBuf, tagOffset, tagIdBuffer);
            tag = new EmvTag(scope, tagIdBuffer, src, srcOffset, length);
        } else {
            tag.setData(src, srcOffset, length);
        }

        return tag;
    }

    /**
     * Add or update BER-TLV EMV tag of one or two bytes of the interface scope.
     */
    public static EmvTag setTag(byte scope, short tagId, byte[] src, short srcOffset, byte length) {
        // Two byte tag entry, a one byte tag is prefixed with '00'
        Util.setShort(tagEntryBuffer, (short) 0, tagId);
        return setTag(scope, tagEntryBuffer, (short) 0, src, srcOffset, length);
    }

    /**
     * Add or update the data objects of BER-TLV coded data, e.g. a record template or FCI Proprietary Template, to memory of the interface
     * scope. Data objects of constructed data objects are added as well. '00' and 'FF' bytes between data objects are padding
     * (EMV Book 3, Annex B).
     */
    public static void setTags(byte scope, byte[] buf, short offset, short length) {
        final short end = (short) (offset + length);
        while (offset < end) {
            if (buf[offset] == (byte) 0x00 || buf[offset] == (byte) 0xFF) {
                offset++;
                continue;
            }

            final short tagOffset = offset;
            short tagLength = tagEntryLength(buf, offset);
            offset += tagLength;
            if (offset >= end) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            short valueLength = (short) (buf[offset] & 0x00FF);
            offset++;
            if (valueLength == (short) 0x81 && offset < end) {
                valueLength = (short) (buf[offset] & 0x00FF);
                offset++;
            } else if (valueLength > (short) 0x7F) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if ((short) (offset + valueLength) > end) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            setTag(scope, buf, tagOffset, buf, offset, (byte) valueLength);
            if (isConstructed(buf, tagOffset)) {
                setTags(scope, buf, offset, valueLength);
            }

            offset += valueLength;
        }
    }

    /**
     * True if the tag entry is a constructed data object (ISO/IEC 8825-1, first tag byte bit 6).
     */
    public static boolean isConstructed(byte[] buf, short offset) {
        return (buf[offset] & (byte) 0x20) != 0;
    }

    /**
     * Find BER-TLV EMV tag of one or two bytes available on the current interface.
     */
    public static EmvTag findTag(short tag) {
        EmvTag found = null;
        for (EmvTag iter = DataStore.current.tagHead; iter != null; iter = iter.next) {
            if (iter.tag[0] == (byte) 0x00 && Util.getShort(iter.tag, (short) 1) == tag && iter.isVisible()) {
                if (iter.scope != SCOPE_ANY) {
                    return iter;
                }
                found = iter;
            }
        }

        return found;
    }

    /**
     * Find BER-TLV EMV tag given as a tag entry available on the current interface, see tagEntryLength.
     */
    public static EmvTag findTag(byte[] buf, short offset) {
        EmvTag found = null;
        for (EmvTag iter = DataStore.current.tagHead; iter != null; iter = iter.next) {
            if (iter.matches(buf, offset) && iter.isVisible()) {
                if (iter.scope != SCOPE_ANY) {
                    return iter;
                }
                found = iter;
            }
        }

        return found;
    }

    /**
     * Remove all stored tags.
     */
    public static short clear() {
        short count = (short) 0;

        for (EmvTag iter = DataStore.current.tagHead; iter != null; ) {
            EmvTag removed = iter;

            iter = iter.next;

            removeTag(removed);
            count++;
        }

        if (JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }

        return count;
    }

    /**
     * Clear all fuzz settings.
     */
    public static void clearFuzz() {
        for (EmvTag iter = DataStore.current.tagHead; iter != null; iter = iter.next) {
            iter.fuzzOffset      = (byte) 0x00;
            iter.fuzzLength      = (byte) 0x00;
            iter.fuzzFlags       = (byte) 0x00;
            iter.fuzzOccurrence  = (byte) 0x00;
        }
    }

    /**
     * Remove tag.
     */
    public static boolean removeTag(short tagId) {
        EmvTag tag = findTag(tagId);
        if (tag == null) {
            return false;
        }

        removeTag(tag);

        return true;
    }

    private static void removeTag(EmvTag tag) {
        EmvTag previousTag = tag.previous;
        EmvTag nextTag = tag.next;

        DataStore store = DataStore.current;

        JCSystem.beginTransaction();

        if (store.tagHead == tag) {
            store.tagHead = nextTag;
        }
        if (store.tagTail == tag) {
            store.tagTail = previousTag;
        }
        if (previousTag != null) {
            previousTag.next = nextTag;
        }
        if (nextTag != null) {
            nextTag.previous = previousTag;
        }

        JCSystem.commitTransaction();
    }

    /**
     * Set the data/value and length of the tag.
     */
    public void setData(byte[] src, short srcOffset, byte length) {
        this.length = length;
        Util.arrayCopy(src, srcOffset, data, (short) 0, (short) (this.length & 0x00FF));
    }

    /**
     * Return first EmvTag instance.
     */
    public static EmvTag getHead() {
        return DataStore.current.tagHead;
    }

    /**
     * Return next EmvTag instance.
     */
    public EmvTag getNext() {
        return next;
    }

    /**
     * Get tag name.
     */
    public byte[] getTag() {
        return tag;
    }

    /**
     * Get tag data/value.
     */
    public byte[] getData() {
        return data;
    }

    /**
     * Get data length.
     */
    public byte getLength() {
        return length;
    }

    /**
     * Serialize tag as BER-TLV to array.
     */
    public short copyToArray(byte[] dst, short dstOffset) {
        short copyOffset = dstOffset;

        copyOffset = copyTagToArray(dst, copyOffset);

        short shortLength = (short) (length & 0x00FF);
        if (shortLength >= 128) {
            dst[copyOffset] = (byte) 0x81;
            copyOffset += (short) 1;
        }

        short lengthOffset = copyOffset;
        copyOffset += (short) 1;
        copyOffset = copyDataToArray(dst, copyOffset);

        dst[lengthOffset] = length;

        // re-write tag length with fuzz overflow?
        if (fuzzLength > 0x00 && (fuzzFlags & (1 << 0)) == 1) {
            // TODO: How to handle the case that tag length would need to be represented as two bytes instead of one?
            dst[lengthOffset] = (byte) (copyOffset - lengthOffset - 1);
        }



        return copyOffset;
    }

    /**
     * Serialize tag without leading zero bytes to array.
     */
    public short copyTagToArray(byte[] dst, short dstOffset) {
        short tagOffset = (short) 0;
        while (tagOffset < (short) (TAG_SIZE - 1) && tag[tagOffset] == (byte) 0x00) {
            tagOffset++;
        }

        return Util.arrayCopyNonAtomic(tag, tagOffset, dst, dstOffset, (short) (TAG_SIZE - tagOffset));
    }

    /**
     * Serialize tag's data to array, i.e. no BER-TLV header.
     */
    public short copyDataToArray(byte[] dst, short dstOffset) {
        short shortLength = (short) (length & 0x00FF);

        Util.arrayCopy(data, (short) 0, dst, dstOffset, shortLength);

        if (fuzzLength > (byte) 0x00) {
            byte doFuzzing = (byte) 0x00;

            if (fuzzOccurrence > (byte) 0x00) {
                EmvApplet.randomData.generateData(EmvApplet.tmpBuffer, (short) 0, (short) 1);
                doFuzzing = (byte) (EmvApplet.tmpBuffer[(short) 0] % fuzzOccurrence);
            }

            if (doFuzzing == (byte) 0x00) {
                EmvApplet.randomData.generateData(dst, (short) (dstOffset + (fuzzOffset & 0x00FF)), (short) (fuzzLength & 0x00FF));

                if (fuzzLength + fuzzOffset > shortLength) {
                    shortLength = (short) ((fuzzLength & 0x00FF) + (fuzzOffset & 0x00FF));
                }
            }
        }

        return (short) (dstOffset + shortLength);
    }
}
