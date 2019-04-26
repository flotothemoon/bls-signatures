package org.chia.jbls;

import java.util.List;
import java.util.Objects;

public final class BLSPublicKey {
	public static final int PUBLIC_KEY_SIZE_BYTES;
	public static final int MESSAGE_HASH_SIZE_BYTES;
    static {
        JNIBLS.ensureJNILoaded();
        PUBLIC_KEY_SIZE_BYTES = _getPublicKeySize();
        MESSAGE_HASH_SIZE_BYTES = _getMessageHashSize();
    }

	private final long nativePtr;
	private byte[] asByteArray = null;

	BLSPublicKey(long nativePtr) {
		this.nativePtr = nativePtr;
	}

	public byte[] toByteArray() {
	    if (this.asByteArray == null) {
            byte[] bytes = new byte[PUBLIC_KEY_SIZE_BYTES];
            _serialize(nativePtr, bytes);

            this.asByteArray = bytes;
	    }

	    return this.asByteArray;
	}

	public static BLSPublicKey aggregate(List<BLSPublicKey> publicKeys) throws BLSException {
        Objects.requireNonNull(publicKeys, "publicKeys is required");

        long[] pKeyPtrs = new long[publicKeys.size()];
        for (int i = 0; i < publicKeys.size(); i++) {
            pKeyPtrs[i] = publicKeys.get(i).nativePtr;
        }

        long aggregatedPtr = _aggregate(pKeyPtrs);
        return new BLSPublicKey(aggregatedPtr);
    }

	public static BLSPublicKey aggregateInsecure(List<BLSPublicKey> publicKeys) throws BLSException {
		Objects.requireNonNull(publicKeys, "publicKeys is required");

		long[] pKeyPtrs = new long[publicKeys.size()];
		for (int i = 0; i < publicKeys.size(); i++) {
			pKeyPtrs[i] = publicKeys.get(i).nativePtr;
		}

		long aggregatedPtr = _aggregateInsecure(pKeyPtrs);
		return new BLSPublicKey(aggregatedPtr);
	}

	public static BLSPublicKey fromBytes(byte[] bytes) throws BLSException {
		return new BLSPublicKey(_constructFromBytes(bytes));
	}

	long getNativePtr() {
	    return this.nativePtr;
	}

	private static native long _aggregateInsecure(long[] ptrs);

	private static native long _aggregate(long[] ptrs);

	private static native long _constructFromBytes(byte[] seed);

	private static native void _serialize(long ptr, byte[] buffer);

	private static native void _delete(long ptr);

	private static native int _getPublicKeySize();

	private static native int _getMessageHashSize();

	@Override
	protected void finalize() {
		_delete(this.nativePtr);
	}
}