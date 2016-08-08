package us.kbase.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
	
	/* should really handle tokens as char[] instead of String so the
	 * char[] can be wiped when it's no longer needed. But since they're going
	 * over the wire they're probably already strings or will be converted to
	 * Strings at some point or another.
	 */
	
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
		if (token == null || token.isEmpty()) {
			throw new IllegalArgumentException(
					"token cannot be null or empty");
		}
		final UserDate ud = cache.get(getTokenDigest(token));
		if (ud == null) {
			return null;
		}
		if (new Date().getTime() - ud.date > MAX_AGE_MS) {
			return null;
		}
		return new AuthToken(token, ud.user);
	}
	
	private String getTokenDigest(final String token) {
		final MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Pretty sure SHA-256 is known, " +
					"something is very broken here", e);
		}
		final byte[] d = digest.digest(token.getBytes(StandardCharsets.UTF_8));
		final StringBuilder sb = new StringBuilder();
		for (final byte b : d) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}
	
	/**
	 * Add a token to the cache. This method assumes the token is valid.
	 * @param token the token to add
	 */
	public void putValidToken(AuthToken token) {
		if (token == null) {
			throw new NullPointerException("token cannot be null");
		}
		cache.put(getTokenDigest(token.getToken()),
				new UserDate(token.getUserName()));
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