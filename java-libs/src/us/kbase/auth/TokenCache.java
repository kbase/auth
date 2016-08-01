package us.kbase.auth;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Caches tokens to avoid network queries to the token provider.
 * 
 * Tokens are cached for 5 minutes.
 * 
 * Tokens are stored until the size of the cache is greater than the maximum
 * allowed size. Tokens are then ordered by most recent access and the oldest
 * tokens are discarded to return the cache to its nominal size.
 * 
 * This class is thread safe.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class TokenCache {
	
	/**
	 * Default nominal size of the cache.
	 */
	final public static int DEFAULT_SIZE = 1000;
	/**
	 * Default maximum size of the cache.
	 */
	final public static int DEFAULT_MAX_SIZE = 2000;
	
	// only non-final so can be tested via reflection.
	private static int MAX_AGE_MS = 5 * 60 * 1000; // 5 min
	
	final private int size;
	final private int maxsize;
	final private ConcurrentHashMap<String, UserDate> cache;
	
	/**
	 * Create a new TokenCache.
	 * @param size the nominal size of the cache in tokens
	 * @param maxsize the maximum size of the cache in tokens
	 */
	public TokenCache(int size, int maxsize) {
		if (size < 1 || maxsize < 1) {
			throw new IllegalArgumentException("size and maxsize must be > 0");
		}
		if (size >= maxsize) {
			throw new IllegalArgumentException("size must be < maxsize");
		}
		this.size = size;
		this.maxsize = maxsize;
		cache = new ConcurrentHashMap<String, UserDate>(maxsize);
	}
	
	/**
	 * Create a new TokenCache with the default max size.
	 * @param size the nominal size of the cache in tokens
	 */
	public TokenCache(int size) {
		this(size, DEFAULT_MAX_SIZE);
	}
	
	/**
	 * Create a new TokenCache with default parameters.
	 */
	public TokenCache() {
		this(DEFAULT_SIZE);
	}
	
	/** Get a token from the cache given its string. Returns null if the 
	 * cache does not contain the token.
	 * @param token the token string.
	 * @return an AuthToken.
	 */
	public AuthToken getToken(final String token) {
		final UserDate ud = cache.get(token);
		if (ud == null) {
			return null;
		}
		if (new Date().getTime() - ud.date > MAX_AGE_MS) {
			return null;
		}
		return new AuthToken(token, ud.user);
	}
	
	/**
	 * Add a token to the cache. This method assumes the token is valid.
	 * @param token the token to add
	 */
	public void putValidToken(AuthToken token) {
		cache.put(token.getToken(), new UserDate(token.getUserName()));
		synchronized (cache) { // block here otherwise all threads may start sorting
			if (cache.size() <= maxsize) {
				return;
			}
			List<DateToken> dts = new ArrayList<DateToken>();
			for (String s: cache.keySet()) {
				dts.add(new DateToken(cache.get(s).date, s));
			}
			Collections.sort(dts);
			for(int i = size; i < dts.size(); i++) {
				cache.remove(dts.get(i).token);
			}
		}
	}
}

class UserDate {
	String user;
	long date;
	
	UserDate(String user) {
		super();
		this.user = user;
		this.date = new Date().getTime();
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("UserDate [user=");
		builder.append(user);
		builder.append(", date=");
		builder.append(date);
		builder.append("]");
		return builder.toString();
	}
}

class DateToken implements Comparable<DateToken>{

	final String token;
	final Date date;
	
	DateToken(long date, String token) {
		this.token = token;
		this.date = new Date(date);
	}
	
	@Override
	public int compareTo(DateToken dt) {
		return -this.date.compareTo(dt.date); //descending
	}
	
}