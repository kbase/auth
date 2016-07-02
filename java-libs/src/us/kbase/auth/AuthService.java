package us.kbase.auth;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * A fairly simple Auth service client for KBase.
 * Usage:
 * 
 * AuthUser user = AuthService.login(user, password);
 * if (AuthService.validateToken(user.getToken())) {
 * 		// There's a valid token! Return the valid user, or just the token, and move along.
 * }
 * 
 * Thus, this provides code for a user to log in to KBase, retrieve a valid Auth token, and
 * optionally validate it.
 * 
 * All tokens seen by this class are cached by the
 * {@link us.kbase.auth.TokenCache} class.
 * 
 * @author wjriehl
 * @author gaprice@lbl.gov
 */
public class AuthService {
	
	private AuthService() {};
	
	private final static AuthConfig DEFAULT_CONFIG = new AuthConfig();
	final static TokenCache TOKEN_CACHE = new TokenCache();
	final static StringCache USER_CACHE = new StringCache();
	final static Pattern INVALID_USERNAME =
			Pattern.compile("[^a-zA-Z0-9_-]");
	
	/**
	 * Logs in a user and returns an AuthUser object, which is more or less a POJO containing basic user attributes,
	 * along with the generated AuthToken.
	 * 
	 * @param userName the username
	 * @param password the password
	 * @param expiry the desired expiration time for the token in seconds.
	 * @return an AuthUser that has been successfully logged in.
	 * @throws AuthException if the credentials are invalid
	 * @throws IOException if there is a problem communicating with the server.
	 */
	public static AuthUser login(
			final String userName,
			final String password,
			final long expiry)
			throws AuthException, IOException {
		return login(userName, password, expiry, DEFAULT_CONFIG);
	}
	
	static AuthUser login(
			final String userName,
			final String password,
			final long expiry,
			final AuthConfig config)
			throws AuthException, IOException {
		// This is the data that will be POSTed to the service.
		// By default (not sure if we *really* need to change it), it fetches all the fields.
		try {
			String dataStr = "user_id=" + URLEncoder.encode(userName, "UTF-8") + 
							 "&password=" + URLEncoder.encode(password, "UTF-8") + 
							 "&cookie=1&fields=user_id,name,email,groups,kbase_sessionid,token,verified,opt_in,system_admin";
			return fetchUser(dataStr, expiry, config);
		}
		catch (UnsupportedEncodingException e) {
			throw new RuntimeException("An unexpected URL encoding exception occurred: " + e.getLocalizedMessage());
		}
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
	public static AuthUser login(String userName, String password)
			throws AuthException, IOException {
		return login(userName, password, AuthToken.DEFAULT_EXPIRES,
				DEFAULT_CONFIG);
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
	 */
	public static RefreshingToken getRefreshingToken(
			final String userName,
			final String password,
			final int refreshIntervalInSeconds)
			throws AuthException, IOException {
		return new RefreshingToken(userName, password,
				refreshIntervalInSeconds);
		
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
	public static AuthUser getUserFromToken(AuthToken token)
			throws AuthException, IOException {
		return getUserFromToken(token, DEFAULT_CONFIG);
	}
	
	static AuthUser getUserFromToken(AuthToken token, AuthConfig config)
			throws AuthException, IOException {
		String dataStr = "token=" + token.toString() +
				 "&fields=user_id,name,email,groups,kbase_sessionid,token,verified,opt_in,system_admin";

		return fetchUser(dataStr, token.getExpiryTime(), config);
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
	public static Map<String, Boolean> isValidUserName(List<String> usernames,
			AuthToken token) throws IOException, AuthException {
		return isValidUserName(usernames, token, DEFAULT_CONFIG);
	}
	
	static Map<String, Boolean> isValidUserName(
			final List<String> usernames,
			final AuthToken token,
			final AuthConfig config) throws IOException, AuthException {
		//TODO WAIT when auth service supports, just query auth service for this
		final List<String> badlist = new ArrayList<String>();
		final Map<String, Boolean> result = new HashMap<String, Boolean>();
		for (String user: usernames) {
			if (user == null) {
				continue;
			}
			if (USER_CACHE.hasString(user)) {
				result.put(user, true);
			} else {
				badlist.add(user);
			}
		}
		Map<String, UserDetail> uds = fetchUserDetail(badlist, token, config);
		for (String user: uds.keySet()) {
			result.put(user, uds.get(user) != null);
		}
		return result;
	}
	
	/**
	 * Get information about users. Note that in order to see all users in the
	 * specified group, the user the provided token
	 * represents must be an administrator of the group. Otherwise users with
	 * private profiles will not be visible.
	 * @param usernames the user names of the users that are the subject of the request
	 * @param token a valid token. If none is provided the method will use the
	 * token from the configuration object used to initialize the AuthService,
	 * if any.
	 * @return a mapping of username to user details.
	 * @throws AuthException if the credentials are invalid
	 * @throws IOException if there is a problem communicating with the server.
	 * @throws IllegalArgumentException if a username is invalid.
	 */
	public static Map<String, UserDetail> fetchUserDetail(
			final List<String> usernames,
			final AuthToken token)
			throws IOException, AuthException {
		return fetchUserDetail(usernames, token, DEFAULT_CONFIG);
	}
	
	static Map<String, UserDetail> fetchUserDetail(
			final List<String> usernames,
			final AuthToken token,
			final AuthConfig config)
			throws IOException, AuthException {
		if (token == null) {
			throw new NullPointerException("token cannot be null");
		}
		//TODO WAIT when auth service supports, just query auth service for this
		final Map<String, UserDetail> result = new HashMap<String, UserDetail>();
		for (String un: usernames) {
			if (un == null) {
				continue;
			}
			result.put(un, null);
			final Matcher m = INVALID_USERNAME.matcher(un);
			if (m.find()) {
				throw new IllegalArgumentException(
						"username " + un + " has invalid character: " + m.group(0));
			}
		}
		if (result.keySet().isEmpty()) {
			return result;
		}
		for (final String name: result.keySet()) {
			URL query = null;
			try {
				query = new URL(config.getGlobusUsersURL().toString()
						+ name);
			} catch (MalformedURLException mue) {
				throw new RuntimeException("globus url " +
						config.getGlobusUsersURL() + 
						" magically has illegal characters", mue);
			}
			final HttpURLConnection conn = (HttpURLConnection) query.openConnection();
			conn.setRequestProperty("X-Globus-Goauthtoken", token.toString());
			conn.setRequestMethod("GET");
			conn.setDoOutput(true);
			conn.setUseCaches(false);
			
			int responseCode = conn.getResponseCode();
			// 200 = found, 403 = private, 404 = doesn't exist
			if (responseCode != 200 && responseCode != 403
					&& responseCode != 404) {
				conn.disconnect();
				throw new AuthException(
						"User detail retrieval failed for user " +
						name + "! Server responded with code " + responseCode +
						" " + conn.getResponseMessage());
			}
			if (responseCode == 200) { //otherwise skip & return null for user
				/** Encoding the HTTP response into JSON format */
				final BufferedReader br = new BufferedReader(
						new InputStreamReader(conn.getInputStream()));
				String responseText = readFromReaderAndClose(br);

				final Map<String, Object> userdetail;
				try {
					@SuppressWarnings("unchecked")
					final Map<String, Object> foo = new ObjectMapper()
						.readValue(responseText, Map.class);
					userdetail = foo;
				} catch (Exception ex) {
					throw new AuthException(ex.getMessage(), ex, responseText);
				}
				final String user = (String) userdetail.get("username");
				USER_CACHE.putString(user);
				result.put(user, new UserDetail(user,
						(String) userdetail.get("email"),
						(String) userdetail.get("fullname")));
			}
		}
		return result;
	}
	
	private static String readFromReaderAndClose(BufferedReader br)
			throws IOException {
		StringBuilder ret = new StringBuilder();
		while (true) {
			String l = br.readLine();
			if (l == null)
				break;
			ret.append(l).append('\n');
		}
		br.close();
		return ret.toString();
	}
	
	/**
	 * Given a data str, describing URL-encoded fields for the auth server, this attempts to authenticate the user
	 * with KBase servers.
	 * 
	 * @param dataStr the data string passed to the auth server.
	 * @param expiry the desired expiration time for the token
	 * @param config the configuration to use
	 * @return an AuthUser that has been authenticated with KBase
	 * @throws AuthException if the credentials are invalid
	 * @throws IOException if there is a problem communicating with the server.
	 */
	static AuthUser fetchUser(
			final String dataStr,
			final long expiry,
			final AuthConfig config)
			throws AuthException, IOException {
		// Start with a null user - if the mapper fails for some reason, we know it's
		// still null (and not uninitialized), and can throw a proper exception.

		//TODO add retries
		try {
			// Build the connection project and set it up.
			final HttpURLConnection conn = (HttpURLConnection)
					config.getAuthLoginURL().openConnection();
			conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			conn.setRequestProperty("Content-Length", String.valueOf(dataStr.getBytes().length));
			conn.setRequestProperty("Content-Language", "en-US");
			conn.setRequestMethod("POST");
			conn.setDoOutput(true);
			conn.setDoInput(true);
			conn.setUseCaches(false);
			
			// Write out the POST data.
			final DataOutputStream writer = new DataOutputStream(conn.getOutputStream());
			writer.writeBytes(dataStr);
			writer.flush();
			writer.close();
			
			// If we don't have a happy response code, throw an exception.
			int responseCode = conn.getResponseCode();
			if (responseCode != 200) {
				conn.disconnect();
				if (responseCode < 500) {
					throw new AuthException("Login failed! Server responded with code " + responseCode + " " + conn.getResponseMessage());
				} else {
					throw new IOException("Server comms failed. Code: " + responseCode + " " + conn.getResponseMessage());
				}
			}

			/** Encoding the HTTP response into JSON format */
			final BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String responseText = readFromReaderAndClose(br);
			
			final AuthUser user;
			try {
				user = new ObjectMapper().readValue(responseText, AuthUser.class);
			} catch (Exception ex) {
				throw new AuthException(ex.getMessage(), ex, responseText);
			}

			if (user == null) { // if still null, throw an exception 
				throw new IOException("Server returned a null object. Code: " + responseCode + " " + conn.getResponseMessage());
			}
			if (user.getToken() != null) {
				user.getToken().setExpiryTime(expiry);
				TOKEN_CACHE.putValidToken(user.getToken());
			}

			br.close();
			conn.disconnect();
			return user;
		}
		catch (UnsupportedEncodingException e) {
			throw new RuntimeException("An unexpected encoding exception occurred: " + e.getLocalizedMessage());
		}
		catch (MalformedURLException e) {
			throw new RuntimeException("An exception occurred while constructing the auth service URL: " + e.getLocalizedMessage());
		}
	}
	
	/**
	 * Given a String representation of an auth token, this validates it against its source in Globus Online.
	 * 
	 * @param tokenStr the token string retrieved from KBase
	 * @return true if the token's valid, false otherwise
	 * @throws AuthException if the credentials are invalid
	 * @throws IOException if there is a problem communicating with the server.
	 */
	public static boolean validateToken(String tokenStr)
			throws TokenFormatException, TokenExpiredException, IOException {
		AuthToken token = new AuthToken(tokenStr);
		return validateToken(token);
	}
	
	/**
	 * This validates a KBase Auth token, and returns true or if valid or false if not.
	 * If the token has expired, it throws a TokenExpiredException.
	 *
	 * @param token the token to validate
	 * @return true if the token's valid, false otherwise
	 * @throws TokenExpiredException if the token is expired (it might be otherwise valid)
	 * @throws IOException if there's a problem communicating with the back end validator.
	 */
	public static boolean validateToken(AuthToken token)
			throws TokenExpiredException, IOException {
		return validateToken(token, DEFAULT_CONFIG);
	}

	static boolean validateToken(AuthToken token, AuthConfig config)
			throws TokenExpiredException, IOException {
		// If it's expired, then it's invalid, and we throw an exception
		if(token.isExpired()) {
			throw new TokenExpiredException("token expired");
		}
		
		// If it's in the cache, then it's valid.
		if(TOKEN_CACHE.hasToken(token)) {
			return true;
		}

		// Otherwise, fetch the user from the Auth Service.
		// If the user is there, then cache this token and return that it's valid.
		try {
			// if we get a user back (and not an exception), then the token is valid.
			String dataStr = "token=" + token.toString() + "&fields=user_id";
			fetchUser(dataStr, token.getExpiryTime(), config);
			TOKEN_CACHE.putValidToken(token);
			return true;
		} catch (AuthException e) {
			// if we get an exception, then an authentication error happened - that's an invalid token.
			return false;
		}
	}

	/**
	 * Disables SSL certificate validation.
	 * 
	 * Once upon a time, we had issues getting the KBase SSL certificate renewed. This isn't a big deal for a web
	 * user - just click through the "Hey, this isn't valid!" page. But going over https would make the Java
	 * HttpsURLConnection have a tizzy fit.
	 * 
	 * Running this method tells the HttpsURLConnection to ignore any certificate validation errors in any subsequent
	 * calls. So if the certificate has errors in the future, run this method before doing any service calls.
	 * 
	 * e.g.
	 * <code>
	 * AuthService.disableCertificateValidation();
	 * AuthService.login(<<credentials>>);
	 * </code>
	 */
	@SuppressWarnings("unused")
	private static void disableCertificateValidation() {
		TrustManager[] trustAllCerts = new TrustManager[] {
			new X509TrustManager() {
				public X509Certificate[] getAcceptedIssuers() {
					return new X509Certificate[0];
				}
				public void checkClientTrusted(X509Certificate[] certs, String authType) {}
				public void checkServerTrusted(X509Certificate[] certs, String authType) {}
			}
		};
		
		HostnameVerifier hv = new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session) { return true; }
		};
		
		try {
			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
			HttpsURLConnection.setDefaultHostnameVerifier(hv);
		} catch (Exception e) {}
	}
	
	/**
	 * Sets the URL that the service should point to. This is the URL that points to the login service:
	 * https://kbase.us/services/authorization/Sessions/Login
	 * 
	 * Before setting the URL, this checks to see if a service exists there with a simple GET request.
	 * If it sees something resembling the KBase auth service, it will set the URL and return 'true'. 
	 * Otherwise, no change is made and 'false' is returned.
	 *
	 * @param url the new URL for the service
	 * @throws IOException if something goes wrong with the connection test.
	 */
	static void checkServiceUrl(URL url) throws IOException {

		HttpURLConnection conn = (HttpURLConnection) url.openConnection();

		int response = conn.getResponseCode();

		// we want to check for a 401 error with this text (or something like it):
		// {"user_id": null, "error_msg": "Must specify user_id and password in POST message body"}
		if (response == 401) {
			BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
			String line;
			String result = "";
			while ((line = reader.readLine()) != null) {
				result += line;
			}
			reader.close();
			conn.disconnect();

			if (!result.contains("\"user_id\": null")) {
				throw new IOException("Auth service URL invalid");
			}
		}
	}
}
