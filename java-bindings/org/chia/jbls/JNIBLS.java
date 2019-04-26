package org.chia.jbls;

public final class JNIBLS {
	private static boolean loadedLibrary = false;
	static void ensureJNILoaded() {
		if (!loadedLibrary) {
			System.loadLibrary("jbls");

			loadedLibrary = true;
		}
	}

	private JNIBLS() {
	    throw new IllegalStateException("Cannot construct");
	}
}
