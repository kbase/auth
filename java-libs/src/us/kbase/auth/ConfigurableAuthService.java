package us.kbase.auth;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * This is a wrapper around the AuthService class that allows configuring the
 * service endpoints, the Globus group, and allows setting a token to use
 * consistently for validating users and fetching user details.
 * 
 * Note that instances of ConfigurableAuthService all share the same cache. The
 * cache is static across all instances of ConfigurableAuthService and the
 * static AuthService class.
 * 
 * AuthUser user = new AuthService().login(user, password);
 * if (new AuthService().validateToken(user.getToken())) {
 * 		// There's a valid token! Return the valid user, or just the token, and move along.
 * }
 * 
 * Thus, this provides code for a user to log in to KBase, retrieve a valid
 * Auth token, and optionally validate it.
 * 
 * All tokens seen by this class are cached by the
 * {@link us.kbase.auth.TokenCache} class.
 * 
 * @author wjriehl
 * @author gaprice@lbl.gov
 */
public class ConfigurableAuthService {
	
	private final AuthConfig config;

	/** Create an authorization service client with the default configuration.
	 * @throws IOException if an IO error occurs.
	 */
	public ConfigurableAuthService() throws IOException {
		this(new AuthConfig());
	}
	
	/** Create an authorization service client with a custom configuration.
	 * @param config the configuration for the auth client.
	 * @throws IOException if an IO error occurs.
	 */
	public ConfigurableAuthService(final AuthConfig config) throws IOException {
		if (config == null) {
			throw new NullPointerException("config cannot be null");
		}
		this.config = config;
		AuthService.checkServiceUrl(this.config.getAuthLoginURL());
	}
	
	/** Returns the configuration of the auth client.
	 * @return the authorization configuration.
	 */
	public AuthConfig getConfig() {
		return config;
	}
	
	/**
	 * Logs in a user and returns an AuthUser object, which is more or less a POJO containing basic user attributes,
	 * along with the generated AuthToken.
	 * 
	 * @param userName the username
	 * @param password the password
	 * @return an AuthUser that has been successfully logged in.
	 * @throws AuthException if the credentials are invalid
	 * @throws IOException if there is a problem communicating with the server.
	 */
	public AuthUser login(String userName, String password)
			throws AuthException, IOException {
		return AuthService.login(userName, password, config);
	}
	
	/** Returns a token that continually refreshes itself and thus never
	 * expires, as long as the credentials are correct.
	 * @param userName the user name of the user who the token will represent.
	 * @param password the password of the user.
	 * @param refreshIntervalInSeconds the how frequently the token should
	 * refresh itself, in seconds. 24 * 60 * 60 is generally reasonable.
	 * @return a auto-refreshing token.
	 * @throws AuthException if the credentials are invalid.
	 * @throws IOException if an IO error occurs.
	 * 
	 * @deprecated This method will fail once the new auth service is deployed.
	 */
	public RefreshingToken getRefreshingToken(
			final String userName,
			final String password,
			final int refreshIntervalInSeconds)
			throws AuthException, IOException {
		return new RefreshingToken(userName, password,
				refreshIntervalInSeconds, this);
		
	}

	/**
	 * Given an AuthToken object for a logged in user, this returns the
	 * AuthUser object representing that user's profile.
	 * 
	 * @param token the token
	 * @return an AuthUser associated with the given token.
	 * @throws AuthException if the credentials are invalid
	 * @throws IOException if there is a problem communicating with the server.
	 */
	public AuthUser getUserFromToken(final AuthToken token)
			throws AuthException, IOException {

		return AuthService.getUserFromToken(token, config);
	}
	
	/**
	 * Checks whether strings are a valid user names. This method relies
	 * on the token provided in the configuration object passed to the
	 * ConfigurableAuthService constructor.
	 * Checks the local cache first to avoid an http call.
	 * @param usernames the usernames
	 * @return a mapping of username to validity.
	 * @throws AuthException if the credentials are invalid
	 * @throws IOException if there is a problem communicating with the server.
	 * @throws IllegalArgumentException if a username is invalid.
	 */
	public Map<String, Boolean> isValidUserName(List<String> usernames)
			throws IOException, AuthException {
		checkToken();
		return isValidUserName(usernames, config.getToken());
	}
	
	/**
	 * Checks whether strings are a valid user names. Note that in order to see
	 * all users in the specified group, the user the provided token
	 * represents must be an administrator of the group. Otherwise users with
	 * private profiles will not be visible.
	 * Checks the local cache first to avoid an http call.
	 * @param usernames the usernames
	 * @param token a valid token
	 * @return a mapping of username to validity.
	 * @throws AuthException if the credentials are invalid
	 * @throws IOException if there is a problem communicating with the server.
	 * @throws IllegalArgumentException if a username is invalid.
	 */
	public Map<String, Boolean> isValidUserName(List<String> usernames,
			AuthToken token) throws IOException, AuthException {
		token = getToken(token);
		return AuthService.isValidUserName(usernames, token, config);
	}
	
	/** Get information about users. This method relies on the token provided
	 * in the configuration object passed to the ConfigurableAuthService
	 * constructor.
	 * @param usernames the user names of the users that are the subject of the request
	 * @return a mapping of username to user details.
	 * @throws AuthException if the credentials are invalid
	 * @throws IOException if there is a problem communicating with the server.
	 * @throws IllegalArgumentException if a username is invalid.
	 */
	public Map<String, UserDetail> fetchUserDetail(List<String> usernames)
			throws IOException, AuthException {
		checkToken();
		return fetchUserDetail(usernames, config.getToken());
	}

	private void checkToken() throws AuthException, IOException {
		if (config.getToken() == null) {
			throw new TokenException(
					"No token specified in the auth client configuration");
		}
	}
	
	/**
	 * Get information about users. Note that in order to see all users in the
	 * specified group, the user the provided token
	 * represents must be an administrator of the group. Otherwise users with
	 * private profiles will not be visible.
	 * @param usernames the user names of the users that are the subject of the
	 * request
	 * @param token a valid token. If none is provided the method will use the
	 * token from the configuration object used to initialize the AuthService,
	 * if any.
	 * @return a mapping of username to user details.
	 * @throws AuthException if the credentials are invalid
	 * @throws IOException if there is a problem communicating with the server.
	 * @throws IllegalArgumentException if a username is invalid.
	 */
	public Map<String, UserDetail> fetchUserDetail(List<String> usernames,
			AuthToken token) throws IOException, AuthException {
		token = getToken(token);
		return AuthService.fetchUserDetail(usernames, token, config);
	}

	private AuthToken getToken(AuthToken token) throws AuthException,
			IOException {
		if (token == null) {
			if (config.getToken() == null) {
				throw new NullPointerException(
						"If no token is specified in the auth client configuration a token must be provided");
			} else {
				return config.getToken();
			}
		}
		return token;
	}
	
	/**
	 * Validates a token and returns a validated token.
	 * 
	 * @param tokenStr the token string to validate.
	 * @return a validated token
	 * @throws IOException if there is a problem communicating with the server.
	 * @throws AuthException if the token is invalid.
	 */
	public AuthToken validateToken(final String tokenStr)
			throws IOException, AuthException {
		return AuthService.validateToken(tokenStr, config);
	}
	
}
