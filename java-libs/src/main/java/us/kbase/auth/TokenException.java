package us.kbase.auth;

public class TokenException extends AuthException {

	private static final long serialVersionUID = 1L;

	public TokenException() {
		super();
	}

	public TokenException(String exception) {
		super(exception);
	}
}