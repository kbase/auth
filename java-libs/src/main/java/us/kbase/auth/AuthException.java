package us.kbase.auth;

import java.lang.Exception;

public class AuthException extends Exception {

	private static final long serialVersionUID = 1L;
	
	private String data = null;

	public AuthException() {
		super();
	}

	public AuthException(String exception) {
		super(exception);
	}

	public AuthException(String exception, Throwable cause) {
		super(exception, cause);
	}

	public AuthException(String exception, Throwable cause, String data) {
		super(exception, cause);
		this.data = data;
	}

	public String getData() {
		return data;
	}
}