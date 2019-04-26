package org.chia.jbls;

public class BLSException extends Exception {
	BLSException(String message) {
		super(message);
	}

	BLSException(String message, Throwable cause) {
		super(message, cause);
	}
}