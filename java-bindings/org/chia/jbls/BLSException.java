package org.chia.jbls;

public class BLSException extends Exception {
	public BLSException(String message) {
		super(message);
	}

	public BLSException(String message, Throwable cause) {
		super(message, cause);
	}
}