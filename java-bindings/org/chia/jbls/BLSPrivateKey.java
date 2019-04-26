package org.chia.jbls;


import java.util.List;
import java.util.Objects;

public final class BLSPrivateKey {
	public static final int PRIVATE_KEY_SIZE_BYTES;
	public static final int MESSAGE_HASH_SIZE_BYTES;
    static {
        JNIBLS.ensureJNILoaded();
        PRIVATE_KEY_SIZE_BYTES = _getPrivateKeySize();
        MESSAGE_HASH_SIZE_BYTES = _getMessageHashSize();
    }

	private final long nativePtr;
	private byte[] asByteArray = null;

	private BLSPrivateKey(long nativePtr) {
		this.nativePtr = nativePtr;
	}

	public byte[] toByteArray() {
	    if (this.asByteArray == null) {
            byte[] bytes = new byte[PRIVATE_KEY_SIZE_BYTES];
            _serialize(nativePtr, bytes);

            this.asByteArray = bytes;
	    }

	    return this.asByteArray;
	}

	public BLSSignature signPrehashed(byte[] messageHash) throws BLSException {
	    Objects.requireNonNull(messageHash, "messageHash is required");

        if (messageHash.length != MESSAGE_HASH_SIZE_BYTES) {
            throw new BLSException("Message Hash must be " + MESSAGE_HASH_SIZE_BYTES + " bytes but is " + messageHash.length);
        }

        long sigPtr = _signPrehashed(this.nativePtr, messageHash);
        return new BLSSignature(sigPtr);
	}

	public static BLSPrivateKey aggregateInsecure(List<BLSPrivateKey> privateKeys) throws BLSException {
		Objects.requireNonNull(privateKeys, "privateKeys is required");

		long[] pKeyPtrs = new long[privateKeys.size()];
		for (int i = 0; i < privateKeys.size(); i++) {
			pKeyPtrs[i] = privateKeys.get(i).nativePtr;
		}

		long aggregatedPtr = _aggregateInsecure(pKeyPtrs);
		return new BLSPrivateKey(aggregatedPtr);
	}

	public static BLSPrivateKey fromSeed(byte[] seed) throws BLSException {
		return new BLSPrivateKey(_constructFromSeed(seed));
	}

	public static BLSPrivateKey fromBytes(byte[] bytes) throws BLSException {
		return new BLSPrivateKey(_constructFromBytes(bytes));
	}

	private static native long _aggregateInsecure(long[] ptrs);

	private static native long _constructFromSeed(byte[] seed);

	private static native long _constructFromBytes(byte[] seed);

	private static native long _signPrehashed(long ptr, byte[] messageHash);

	private static native void _serialize(long ptr, byte[] buffer);

	private static native void _delete(long ptr);

	private static native int _getPrivateKeySize();

	private static native int _getMessageHashSize();

	@Override
	protected void finalize() {
		_delete(this.nativePtr);
	}
}