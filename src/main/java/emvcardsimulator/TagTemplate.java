package emvcardsimulator;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class TagTemplate {

    private byte[] data;
    private byte   length;

    public TagTemplate() {
        data = new byte[255];
        this.length = length;
    }

    /**
     * Set BER-TLV EMV tag list. All tags should be stored as EmvTag before serialization.
     */
    public void setData(byte[] src, short srcOffset, byte length) {
        if (length % 2 != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        this.length = length;
        Util.arrayCopy(src, srcOffset, data, (short) 0, (short) (this.length & 0x00FF));
    }

    /**
     * Get BER-TLV EMV tag list.
     */
    public byte[] getData() {
        return data;
    }

    /**
     * Get BER-TLV EMV tag list length.
     */
    public byte getLength() {
        return length;
    }

    /**
     * Retrieve all tag data from EmvTag and copy to destination array as BER-TLV encoded.
     */
    public short expandTlvToArray(byte[] dst, short dstOffset) {

        short dataOffset = dstOffset;
        for (short i = (short) 0; i < (short) (this.length & 0x00FF); i += (short) 2) {
            short tagId = Util.getShort(data, i);

            EmvTag tag = EmvTag.findTag(tagId);

            if (tag == null) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            dataOffset = tag.copyToArray(dst, dataOffset);
        }

        return dataOffset;
    }

    /**
     * Retrieve all tag data from EmvTag and copy to destination array only the tag data values without corresponding TLV headers.
     */
    public short expandTagDataToArray(byte[] dst, short dstOffset) {

        short dataOffset = dstOffset;
        for (short i = (short) 0; i < (short) (this.length & 0x00FF); i += (short) 2) {
            short tagId = Util.getShort(data, i);

            EmvTag tag = EmvTag.findTag(tagId);

            if (tag == null) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            dataOffset = tag.copyDataToArray(dst, dataOffset);
        }

        return dataOffset;
    }

    /**
     * Serialize template's data to array AS-IS, i.e. template is raw data or should not be interpreted from EmvTag.
     */
    public short copyDataToArray(byte[] dst, short dstOffset) {
        short shortLength = (short) (length & 0x00FF);

        Util.arrayCopy(data, (short) 0, dst, dstOffset, shortLength);

        return (short) (dstOffset + shortLength);
    }
}
