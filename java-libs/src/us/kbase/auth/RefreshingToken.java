package us.kbase.auth;

import java.io.IOException;
import java.util.Date;

import us.kbase.auth.AuthException;
import us.kbase.auth.AuthService;
import us.kbase.auth.AuthToken;

/** An auto-refreshing token. The token refreshes itself periodically and so
 * can never expire as long as the credentials are valid.
 * @author gaprice@lbl.gov
 * 
 * @deprecated This class will fail once the new auth service is deployed.
 *
 */
public class RefreshingToken {
	
	final private String user;
	final private String password;
	final private int refreshIntervalMSec;
	final private ConfigurableAuthService auth;
	private AuthToken token;
	private Date refreshDate;
	
	RefreshingToken(
			final String user,
			final String password,
			final int refreshIntervalSeconds) 
			throws AuthException, IOException {
		this(user, password, refreshIntervalSeconds, null);
	}
	
	RefreshingToken(
			final String user,
			final String password,
			final int refreshIntervalSeconds,
			final ConfigurableAuthService auth)
			throws AuthException, IOException {
		checkString(user, "user");
		checkString(password, "password");
		if (refreshIntervalSeconds < 0) {
			throw new IllegalArgumentException(
					"refreshInterval must be 0 or greater");
		}
		this.user = user;
		this.password = password;
		this.refreshIntervalMSec = refreshIntervalSeconds * 1000;
		this.auth = auth;
		this.token = login(user, password);
		this.refreshDate = new Date();
	}
	
	private AuthToken login(final String user, final String password)
			throws AuthException, IOException {
		if (auth == null) {
			return AuthService.login(user, password).getToken();
		} else {
			return auth.login(user, password).getToken();
		}
	}
	
	/** Returns the token.
	 * @return the token.
	 * @throws AuthException if the user credentials are no longer valid.
	 * @throws IOException if an IO error occurs.
	 */
	public synchronized AuthToken getToken()
			throws AuthException, IOException {
		if (new Date().getTime() - refreshDate.getTime()
				> refreshIntervalMSec) {
			this.token = login(user, password);
			this.refreshDate = new Date();
		}
		return token;
	}
	
	private static void checkString(final String s, final String sname) {
		if (s == null || s.isEmpty()) {
			throw new IllegalArgumentException(sname + 
					" cannot be null or the empty string");
		}
	}
}
