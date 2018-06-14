package us.kbase.auth;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A simple class defining an authenticated user. This contains a series of
 * getters and setters for exchanging user information.
 * 
 * Mostly, this is used for unmarshalling an authentication response from KBase.
 * @author wjriehl
 * @author gaprice@lbl.gov
 *
 */
public class AuthUser {
	@JsonProperty("user_id")
	private String userId = null;
	private String email = null;
	private String fullName = null;
	private AuthToken token = null;

	private AuthUser() { }

	@JsonProperty("user_id")
	public String getUserId() {
		return userId;
	}
	@JsonProperty("email")
	public String getEmail() {
		return email;
	}
	
	/**
	 * Returns the token associated with this user as the AuthToken object.
	 * @return an AuthToken object.
	 */
	@JsonProperty("token")
	public AuthToken getToken() {
		return token;
	}
	

	/**
	 * Returns the token associated with this user as its original string.
	 * @return an authentication token String.
	 */
	public String getTokenString() {
		return token.getToken();
	}
	
	@JsonProperty("name")
	public String getFullName() {
		return fullName;
	}
	
}