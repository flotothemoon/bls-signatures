package org.chia.jbls;

import java.util.concurrent.atomic.AtomicBoolean;

public final class JNIBLS {
	private static AtomicBoolean loadedLibrary = new AtomicBoolean(false);
	static void ensureJNILoaded() {
		if (loadedLibrary.compareAndSet(false, true)) {
			System.loadLibrary("jbls");
		}
	}

	private JNIBLS() {
	    throw new IllegalStateException("Cannot construct");
	}
}
