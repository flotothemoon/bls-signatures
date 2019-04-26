package org.chia.jbls;

public class BLSPrivateKey {
	static {
		JNIBLS.ensureJNILoaded();
	}

	public static final int PRIVATE_KEY_SIZE_BYTES = _getPrivateKeySize();

	private static native int _getPrivateKeySize();
}
