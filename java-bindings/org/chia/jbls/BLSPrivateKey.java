package org.chia.jbls;


import java.util.List;
import java.util.Objects;

public final class BLSPrivateKey {
	public static final int PRIVATE_KEY_SIZE_BYTES;
    static {
        JNIBLS.ensureJNILoaded();
        PRIVATE_KEY_SIZE_BYTES = _getPrivateKeySize();
    }

	private final long privateKeyPtr;
	private byte[] asByteArray = null;

	private BLSPrivateKey(long privateKeyPtr) {
		this.privateKeyPtr = privateKeyPtr;
	}

	public byte[] toByteArray() {
	    if (this.asByteArray == null) {
            byte[] bytes = new byte[PRIVATE_KEY_SIZE_BYTES];
            _serialize(privateKeyPtr, bytes);

            this.asByteArray = bytes;
	    }

	    return this.asByteArray;
	}

	public static BLSPrivateKey aggregateInsecure(List<BLSPrivateKey> privateKeys) {
		Objects.requireNonNull(privateKeys, "privateKeys is required");

		long[] pKeyPtrs = new long[privateKeys.size()];
		for (int i = 0; i < privateKeys.size(); i++) {
			pKeyPtrs[i] = privateKeys.get(i).privateKeyPtr;
		}

		long aggregatedPtr = _aggregateInsecure(pKeyPtrs);
		return new BLSPrivateKey(aggregatedPtr);
	}

	public static BLSPrivateKey fromSeed(byte[] seed) {
		return new BLSPrivateKey(_constructFromSeed(seed));
	}

	public static BLSPrivateKey fromBytes(byte[] bytes) {
		return new BLSPrivateKey(_constructFromBytes(bytes));
	}

	private static native long _aggregateInsecure(long[] ptrs);

	private static native long _constructFromSeed(byte[] seed);

	private static native long _constructFromBytes(byte[] seed);

	private static native void _serialize(long ptr, byte[] buffer);

	private static native void _delete(long ptr);

	private static native int _getPrivateKeySize();

	@Override
	protected void finalize() {
		_delete(this.privateKeyPtr);
	}
}