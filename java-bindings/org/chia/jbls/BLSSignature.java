package org.chia.jbls;

import java.util.List;
import java.util.Objects;

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

    public boolean verify(BLSPublicKey[] publicKeys, byte[][] messageHashes) {
        Objects.requireNonNull(publicKeys, "publicKeys is required");
        Objects.requireNonNull(messageHashes, "messageHashes is required");

        if (publicKeys.length != messageHashes.length) {
            throw new IllegalArgumentException("Must be same amount of keys and hashes, was "
                + publicKeys.length + " and " + messageHashes.length);
        }

        if (publicKeys.length == 0) {
            throw new IllegalArgumentException("");
        }

        long[] publicKeyPtrs = new long[publicKeys.length];
        for (int i = 0; i < publicKeys.length; i++) {
            publicKeyPtrs[i] = publicKeys[i].getNativePtr();
        }

        return _verify(this.nativePtr, publicKeyPtrs, messageHashes);
    }

    @Override
    protected void finalize() {
        _delete(this.nativePtr);
    }

	long getNativePtr() {
	    return this.nativePtr;
	}

    public static BLSSignature aggregate(List<BLSSignature> signatures) {
		long[] sigPtrs = new long[signatures.size()];
		for (int i = 0; i < signatures.size(); i++) {
			sigPtrs[i] = signatures.get(i).nativePtr;
		}

		long aggregatedPtr = _aggregate(sigPtrs);
		return new BLSSignature(aggregatedPtr);
    }

	public static BLSSignature fromBytes(byte[] bytes) {
		return new BLSSignature(_constructFromBytes(bytes));
	}

	private static native long _aggregate(long[] ptrs);

	private static native long _constructFromBytes(byte[] seed);

	private static native void _serialize(long ptr, byte[] buffer);

    private static native boolean _verify(long ptr, long[] pubKeyPtrs, byte[][] messageHashes);

    private static native void _delete(long ptr);

    private static native int _getSignatureSize();
}