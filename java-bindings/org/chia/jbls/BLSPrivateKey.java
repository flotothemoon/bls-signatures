package org.chia.jbls;

public final class BLSPrivateKey {
	static {
		JNIBLS.ensureJNILoaded();
	}

	private final long privateKeyPtr;

	private BLSPrivateKey(long privateKeyPtr) {
	    this.privateKeyPtr = privateKeyPtr;
	}

	public static final int PRIVATE_KEY_SIZE_BYTES = _getPrivateKeySize();

    public static BLSPrivateKey fromSeed(byte[] seed) {
        return new BLSPrivateKey(_constructFromSeed(seed));
    }

    private static native long _constructFromSeed(byte[] seed);

    private static native void _delete(long ptr);

	private static native int _getPrivateKeySize();

	@Override
	protected void finalize() {
	    _delete(this.privateKeyPtr);
	}
}
