package org.chia.jbls;

public final class BLSSignature {
    public static final int SIGNATURE_SIZE_BYTES;
    static {
        JNIBLS.ensureJNILoaded();
        SIGNATURE_SIZE_BYTES = _getSignatureSize();
    }

	private final long nativePtr;
	private byte[] asByteArray = null;

    BLSSignature(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    public byte[] toByteArray() {
        if (this.asByteArray == null) {
            byte[] bytes = new byte[SIGNATURE_SIZE_BYTES];
            _serialize(nativePtr, bytes);

            this.asByteArray = bytes;
        }

        return this.asByteArray;
    }

    @Override
    protected void finalize() {
        _delete(this.nativePtr);
    }

	public static BLSSignature fromBytes(byte[] bytes) {
		return new BLSSignature(_constructFromBytes(bytes));
	}

	private static native long _constructFromBytes(byte[] seed);

	private static native void _serialize(long ptr, byte[] buffer);

    private static native void _delete(long ptr);

    private static native int _getSignatureSize();
}