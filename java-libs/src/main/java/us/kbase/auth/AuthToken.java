package us.kbase.auth;

/**
 * An authorization token.
 * 
 * @author wjriehl
 * @author gaprice@lbl.gov
 *
 */

public class AuthToken {
	final private String tokenStr;
	private String userName;
	
	/**
	 * Construct a token with a token and a user name.
	 * 
	 * @param token the token string.
	 * @param user the user name.
	 */
	public AuthToken(final String token, final String user) {
		if (token == null || token.isEmpty()) {
			throw new IllegalArgumentException(
					"token cannot be null or empty");
		}
		if (user == null || user.isEmpty()) {
			throw new IllegalArgumentException("user cannot be null or empty");
		}
		this.tokenStr = token;
		this.userName = user;
	}
	
	/* for jackson */
	@SuppressWarnings("unused")
	private AuthToken(final String token) {
		if (token == null || token.isEmpty()) {
			throw new IllegalArgumentException(
					"token cannot be null or empty");
		}
		this.tokenStr = token;
		this.userName = null;
	}
	
	/* Used for setting the username when creating the token, since Jackson
	 * won't do it for us.
	 */
	void setUserName(final String userName) {
		this.userName = userName;
	}
	
	/**
	 * Returns the user's name.
	 * @return the user name
	 */
	public String getUserName() {
		return userName;
	}
	
	/**
	 * Returns the token as a string.
	 * @return the token string.
	 * 
	 */
	public String getToken() {
		return tokenStr;
	}
	
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("AuthToken [tokenStr=");
		builder.append(tokenStr);
		builder.append(", userName=");
		builder.append(userName);
		builder.append("]");
		return builder.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((tokenStr == null) ? 0 : tokenStr.hashCode());
		result = prime * result + ((userName == null) ? 0 : userName.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		AuthToken other = (AuthToken) obj;
		if (tokenStr == null) {
			if (other.tokenStr != null) {
				return false;
			}
		} else if (!tokenStr.equals(other.tokenStr)) {
			return false;
		}
		if (userName == null) {
			if (other.userName != null) {
				return false;
			}
		} else if (!userName.equals(other.userName)) {
			return false;
		}
		return true;
	}
}
