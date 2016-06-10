package us.kbase.auth;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * Describes an AuthToken as used in KBase.
 * 
 * This takes in a string in the token format and parses it out into this AuthToken object.
 * This object makes each of the token attributes readily available for the user.
 * @author wjriehl
 * @author gaprice@lbl.gov
 *
 */

public class AuthToken {
	/**
	 * The default token expiration time in seconds.
	 */
	public static final long DEFAULT_EXPIRES = 60 * 24 * 60 * 60;
	final private String tokenStr;
	final private String userName;
	final private String tokenId;
	final private String clientId;
	final private Date issued;
	final private String tokenType;
	final private String signingSubject;
	final private String signature;
	final private String tokenData;
	@JsonIgnore
	private long expireTime = DEFAULT_EXPIRES;
	
	/**
	 * The standard constructor for an AuthToken takes a token string and parses it into
	 * the various pieces used by this class.
	 * 
	 * If the token is badly formatted or missing components, it throws an IOException.
	 * @param token the token string.
	 * @throws TokenFormatException if the token could not be parsed.
	 */
	public AuthToken(String token) throws TokenFormatException {
		this(token, DEFAULT_EXPIRES);
	}
	
	/**
	 * The standard constructor for an AuthToken takes a token string and parses it into
	 * the various pieces used by this class.
	 * 
	 * If the token is badly formatted or missing components, it throws an IOException.
	 * @param token the token string.
	 * @param expiry the desired lifetime of the token.
	 * @throws TokenFormatException if the token could not be parsed.
	 */
	public AuthToken(String token, long expiry) throws TokenFormatException {
		/*
		 * Parses the KBase OAuth token into all of its fields and values.
		 * e.g. "un" -> username, "tokenid" -> the token UUID, etc.
		 *
		 * List of fields (case sensitive!): 
		 * un == user name
		 * tokenid == token UUID
		 * expiry == expiration time in seconds since the Time Epoch
		 * client_id == user ID
		 * token_type == "Bearer" or other type of token (probably Bearer)
		 * SigningSubject == URL of signing authority
		 * sig == token signature
		 * tokenData == see below
		 * 
		 * This also includes a separate field called "tokenData". This maps to the part of the token string that needs to be validated
		 * against the signature (in the "sig" field).
		 */
		setExpiryTime(expiry);
		this.tokenStr = token;
		Map<String, String> parsed = new HashMap<String, String>();
		/**
		 * Expect the token to be of the following format:
		 * "key1=value1|key2=value2|key3=value3|..."
		 * So, '|' and '=' are expected to be only present as delimiters.
		 */
		String[] tokenFields = token.split("[|]");
		for (String field : tokenFields) {
			String[] keyValuePair = field.split("[=]");
			
			// Should be exactly 2 elements here. If not == bad news.
			if (keyValuePair.length != 2) {
				throw new TokenFormatException("Auth token is in the incorrect format, near '" + field + "'");
			}
			parsed.put(keyValuePair[0], keyValuePair[1]);
		}

		// Everything up to '|sig=' is the token data, so grab that.
		int sigPos = token.indexOf("|sig=");

		// If we can't find that fragment, or it's at the end of the string, throw an error - there's no sig present!
		if (sigPos == -1 || token.length() < sigPos+5) {
			throw new TokenFormatException("Auth token is in the incorrect format - might be missing the signature?");
		}

		userName = parsed.get("un");
		tokenId = parsed.get("tokenid");
		// Globus expiry is currently set to issue date (which is not stored in 
		// token) + 1 year. Will need to change this code when the authservice
		// provides the issue date.
		final Date exp = new Date(Long.parseLong(parsed.get("expiry")) * 1000);
		final Calendar cal = Calendar.getInstance();
		cal.setTime(exp);
		cal.add(Calendar.YEAR, -1);
//		cal.add(Calendar.DAY_OF_YEAR, 1);
		issued = cal.getTime();
		clientId = parsed.get("client_id");
		tokenType = parsed.get("token_type");
		signingSubject = parsed.get("SigningSubject");
		signature = parsed.get("sig");
		tokenData = token.substring(0, sigPos);
	}
	
	/**
	 * Set the lifetime of this token in seconds.
	 * @param seconds the lifetime of this token.
	 */
	@JsonIgnore
	void setExpiryTime(long seconds) {
		if(seconds < 0) {
			throw new IllegalArgumentException("seconds must be positive");
		}
		expireTime = seconds;
	}
	
	/**
	 * Get the lifetime of this token.
	 * @return the number of seconds past the issue date when this token will
	 * expire.  
	 */
	public long getExpiryTime() {
		return expireTime;
	}

	/**
	 * Returns the user's name.
	 * @return the user name
	 */
	public String getUserName() {
		return userName;
	}
	
	/**
	 * Returns the ID of the token.
	 * @return the token ID
	 */
	public String getTokenId() {
		return tokenId;
	}
	
	/**
	 * Returns the client's ID.
	 * @return the client's ID
	 */
	public String getClientId() {
		return clientId;
	}
	
	/**
	 * Get the issue date for this token.
	 * @return the issue date
	 */
	public Date getIssueDate() {
		return issued;
	}
	
	/**
	 * Returns the type of token that was generated.
	 * @return the token type
	 */
	public String getTokenType() {
		return tokenType;
	}
	
	/**
	 * Returns the signing subject for this token (typically a globus online URL)
	 * @return the signing subject
	 */
	public String getSigningSubject() {
		return signingSubject;
	}
	
	/**
	 * Returns the signature for the token.
	 * @return the signature
	 */
	public String getSignature() {
		return signature;
	}
	
	/**
	 * Returns "token data" - the content of the entire token without the signature.
	 * @return the token data
	 */
	public String getTokenData() {
		return tokenData;
	}
	
	/**
	 * Tests whether this token has expired.
	 * @return <code>true</code> if this token is expired, <code>false</code>
	 * otherwise.
	 */
	public boolean isExpired() {
//		 System.out.println("Expire time: " + expireTime);
//		 System.out.println("Issued time: " + issued.getTime());
//		 System.out.println("Current time: " + new Date().getTime());
//		 System.out.println("Issued+expired: " + (issued.getTime() + (expireTime * 1000)));

		return new Date().getTime() - issued.getTime() > expireTime * 1000;
	}
	
	/**
	 * Returns a string representation of the token - this is identical to the token string that was generated by the service.
	 * @return a string representation of the token
	 */
	public String toString() {
		return tokenStr;
	}
}
