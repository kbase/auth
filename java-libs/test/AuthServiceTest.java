import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLEncoder;

import javax.net.ssl.HttpsURLConnection;

import us.kbase.auth.AuthConfig;
import us.kbase.auth.AuthService;
import us.kbase.auth.AuthToken;
import us.kbase.auth.AuthUser;
import us.kbase.auth.AuthException;
import us.kbase.auth.ConfigurableAuthService;
import us.kbase.auth.StringCache;
import us.kbase.auth.TokenCache;
import us.kbase.auth.TokenException;
import us.kbase.auth.UserDetail;

public class AuthServiceTest {
	private static final String TEST_UID = "kbasetest";
	private static final String TEST_PW = System.getProperty("test.user.password");

	private static final String FULL_NAME = "KBase Test Account";
	private static final String EMAIL = "kbasetest.globus@gmail.com";
	private static final List<AuthToken> TEST_TOKENS = new ArrayList<AuthToken>();
	private static final List<AuthToken> uncachedTokens = new ArrayList<AuthToken>();
	private static List<String> testStrings;


	//TODO LATER will need to make the tests take a token vs. uid/pwd
	
	// Fetched before any tests are run - this test user is then used in the various POJO tests.
	private static AuthUser testUser;
	private static AuthUser testUser2;

	//TODO testing of configurable auth service
	
	@BeforeClass
	public static void loginTestUser() throws Exception {
		System.out.println("Setting up test user for AuthUser and AuthToken testing...");
		try {
			testUser = AuthService.login(TEST_UID, TEST_PW);
			testUser2 = new ConfigurableAuthService().login(TEST_UID, TEST_PW);
			int tokens = 5;
			for(int i = 0; i < tokens; i++) {
				System.out.println("Getting token " + (i + 1) + "/" + tokens);
				TEST_TOKENS.add(AuthService.login(TEST_UID, TEST_PW).getToken());
			}
			tokens = 4;
			for(int i = 0; i < tokens; i++) {
				System.out.println("Getting uncached token " + (i + 1) + "/" + tokens);
				uncachedTokens.add(getUncachedToken());
			}
		}
		catch (Exception e) {
			System.out.println("Setup failed to log in a test user for AuthUser and AuthToken tests!");
			System.out.println("Not running any tests!");
			throw e;
		}
		testStrings = Arrays.asList("string1", "string2", "string3", "string4", "string5");
		System.out.println("Done! Beginning testing....");
	}
	
	public static AuthToken getUncachedToken() throws Exception {
		String dataStr = "user_id=" + URLEncoder.encode(TEST_UID, "UTF-8") + 
				 "&password=" + URLEncoder.encode(TEST_PW, "UTF-8") + 
				 "&cookie=1&fields=user_id,name,email,token";
		HttpsURLConnection conn = (HttpsURLConnection)
				new AuthConfig().getAuthLoginURL().openConnection();
		conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		conn.setRequestProperty("Content-Length", String.valueOf(dataStr.getBytes().length));
		conn.setRequestProperty("Content-Language", "en-US");
		conn.setRequestMethod("POST");
		conn.setDoOutput(true);
		conn.setDoInput(true);
		conn.setUseCaches(false);
		
		// Write out the POST data.
		DataOutputStream writer = new DataOutputStream(conn.getOutputStream());
		writer.writeBytes(dataStr);
		writer.flush();
		writer.close();
		
		// If we don't have a happy response code, throw an exception.
		int responseCode = conn.getResponseCode();
		if (responseCode != 200) {
			conn.disconnect();
			throw new AuthException("Login failed! Server responded with code " + responseCode + " " + conn.getResponseMessage());
		}

		/** Encoding the HTTP response into JSON format */
		BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));

		AuthToken t = new ObjectMapper().readValue(br, AuthUser.class)
				.getToken();
		Method m = t.getClass().getDeclaredMethod("setUserName", String.class);
		m.setAccessible(true);
		m.invoke(t, TEST_UID);
		return t;
	}

	@AfterClass
	public static void cleanup() {
		System.out.println("Done testing!");
	}
	
	//test tokencache
	@Test
	public void authTokenConstruction() throws Exception {
		AuthToken t = new AuthToken("foo", "bar");
		assertThat("incorrect token", t.getToken(), is("foo"));
		assertThat("incorrect user", t.getUserName(), is("bar"));
		
		failMakeToken(null, "user", "token cannot be null or empty");
		failMakeToken("", "user", "token cannot be null or empty");
		failMakeToken("bar", null, "user cannot be null or empty");
		failMakeToken("bar", "", "user cannot be null or empty");
	}
	
	private void failMakeToken(String token, String user, String exp) {
		try {
			new AuthToken(token, user);
			fail("created bad token");
		} catch (IllegalArgumentException got) {
			assertThat("incorrect exception message", got.getMessage(),
					is(exp));
		}
	}

	//test tokencache
	@Test
	public void tokenCacheDropsOldTokensOnResize() throws Exception {
		TokenCache tc = new TokenCache(2, 4);
		tc.putValidToken(TEST_TOKENS.get(0));
		Thread.sleep(2);
		tc.putValidToken(TEST_TOKENS.get(1));
		Thread.sleep(2);
		tc.putValidToken(TEST_TOKENS.get(2));
		Thread.sleep(2);
		tc.putValidToken(TEST_TOKENS.get(3));
		Thread.sleep(2);
		tc.putValidToken(TEST_TOKENS.get(0)); // reset the timer
		assertThat("failure - cache missing tokens",
				tc.getToken(TEST_TOKENS.get(0).getToken()),
				is(TEST_TOKENS.get(0)));
		//make sure oldest token still there
		assertThat("failure - cache missing tokens",
				tc.getToken(TEST_TOKENS.get(1).getToken()),
				is(TEST_TOKENS.get(1)));
		Thread.sleep(2);
		tc.putValidToken(TEST_TOKENS.get(4));
		boolean[] hasToken = {true, false, false, false, true};
		for (int i = 0; i < hasToken.length; i++) {
			if (hasToken[i]) {
				assertNotNull("cache missing token " + i,
						tc.getToken(TEST_TOKENS.get(i).getToken()));
			} else {
				assertNull("cache contains token " + i,
						tc.getToken(TEST_TOKENS.get(i).getToken()));
			}
		}
	}
	
	@Test
	public void tokenCacheDropsExpiredTokens() throws Exception {
		TokenCache tc = new TokenCache(2, 3);
		Field f = tc.getClass().getDeclaredField("MAX_AGE_MS");
		f.setAccessible(true);
		f.set(tc, 70);
		for (int i = 0; i <= 2; i++) {
			tc.putValidToken(TEST_TOKENS.get(i));
			Thread.sleep(50);
		}
		boolean[] hasToken = {false, false, true};
		for (int i = 0; i < hasToken.length; i++) {
			if (hasToken[i]) {
				assertNotNull("cache missing token " + i,
						tc.getToken(TEST_TOKENS.get(i).getToken()));
			} else {
				assertNull("cache contains token " + i,
						tc.getToken(TEST_TOKENS.get(i).getToken()));
			}
		}
		f.set(tc, 5 * 60 * 1000); //reset to default
	}
	
	//test StringCache
	@Test
	public void stringCacheDropsOldStrings() throws InterruptedException {
		StringCache sc = new StringCache(2, 4);
		sc.putString(testStrings.get(0));
		Thread.sleep(50);
		sc.putString(testStrings.get(1));
		Thread.sleep(50);
		assertTrue("failure - cache missing strings", sc.hasString(testStrings.get(0)));
		sc.putString(testStrings.get(2));
		Thread.sleep(50);
		sc.putString(testStrings.get(3));
		Thread.sleep(50);
		assertTrue("failure - cache missing strings", sc.hasString(testStrings.get(0)));
		sc.putString(testStrings.get(4));
		boolean[] expected = {true, false, false, false, true};
		for (int i = 0; i < expected.length; i++) {
			assertEquals("failure - cache retained wrong strings", expected[i], sc.hasString(testStrings.get(i)));
			
		}
	}
	
	@Test
	public void stringCacheDropsExpiredStrings() throws InterruptedException {
		StringCache sc = new StringCache(2, 3);
		try {
			sc.hasString(null);
			fail("string cache accepted a null");
		} catch (NullPointerException npe) {
			assertThat("NPE text correct", npe.getLocalizedMessage(), is("string cannot be null"));
		}
		try {
			sc.putString(null);
			fail("string cache accepted a null");
		} catch (NullPointerException npe) {
			assertThat("NPE text correct", npe.getLocalizedMessage(), is("string cannot be null"));
		}
		sc.setExpiry(2);
		assertThat("failure - expiry time not set correctly", new Long(sc.getExpiry()), is(new Long(2)));
		sc.putString(testStrings.get(0));
		Thread.sleep(1500);
		//touch to reset touched time of string, but not added time
		assertThat("failure - missing non-expired String", sc.hasString(testStrings.get(0)), is(true));
		Thread.sleep(1000); //now should be expired but touched within 1 sec
		sc.putString(testStrings.get(1));
		Thread.sleep(50);
		sc.putString(testStrings.get(2));
		Thread.sleep(50);
		sc.putString(testStrings.get(3));
		assertThat("failure expired string is still in cache", sc.hasString(testStrings.get(0)), is(false));
		boolean[] expected = {false, false, true, true};
		for (int i = 0; i < expected.length; i++) {
			assertEquals("failure - cache retained wrong strings", expected[i], sc.hasString(testStrings.get(i)));
			
		}
	}
	

	// test AuthToken POJO stuff - make sure all fields are non-null
	@Test
	public void checkUserSame() throws Exception {
		assertThat("users have same id", testUser.getUserId(), is(testUser2.getUserId()));
		assertThat("users have same full name", testUser.getFullName(), is(testUser2.getFullName()));
		assertThat("users have same email", testUser.getEmail(), is(testUser2.getEmail()));
	}
	
	// done with AuthToken POJO tests.


	// test AuthUser POJO stuff - make sure all fields are non-null, and profile matches up.
	@Test
	public void testGetUserName() {
		org.junit.Assert.assertEquals("failure - incorrect user name", TEST_UID, testUser.getUserId());
	}

	@Test
	public void testGetUserFullName() {
		org.junit.Assert.assertEquals("failure - incorrect user name",
				FULL_NAME, testUser.getFullName());
	}

	@Test
	public void testUserEmail() {
		org.junit.Assert.assertEquals("failure - incorrect email address",
				EMAIL, testUser.getEmail());
	}

	@Test
	public void testUserHasToken() {
		org.junit.Assert.assertNotNull("failure - user doesn't have a token", testUser.getToken());
	}

	// done with AuthUser tests.


	// test AuthService methods
	
	//TODO TEST LATER delete this when refreshing tokens are removed
	@SuppressWarnings("deprecation")
	@Test
	public void configObjectWithRefreshingToken() throws Exception {
		
		try {
			new ConfigurableAuthService(null);
			fail("init auth service with null config");
		} catch (NullPointerException npe) {
			assertThat("correct exception message", npe.getLocalizedMessage(),
					is("config cannot be null"));
		}
		//defaults
		AuthConfig d = new AuthConfig();
		assertThat("correct KBase url", d.getAuthServerURL(),
				is(new URL("https://www.kbase.us/services/authorization/")));
		assertThat("correct globus url", d.getGlobusURL(),
				is(new URL("https://nexus.api.globusonline.org/")));
		assertThat("correct group id", d.getKbaseUsersGroupID(),
				is(UUID.fromString("99d2a548-7218-11e2-adc0-12313d2d6e7f")));
		assertThat("correct token", d.getRefreshingToken(), is((us.kbase.auth.RefreshingToken) null));
		assertThat("correct full KBase url", d.getAuthLoginURL(),
				is(new URL("https://www.kbase.us/services/authorization/Sessions/Login")));
		assertThat("correct full globus url", d.getGlobusGroupMembersURL(),
				is(new URL("https://nexus.api.globusonline.org/groups/99d2a548-7218-11e2-adc0-12313d2d6e7f/members/")));
		
		//custom
		us.kbase.auth.RefreshingToken rt = AuthService.getRefreshingToken(
				TEST_UID, TEST_PW, 10000);
		AuthConfig c = new AuthConfig()
				.withGlobusAuthURL(new URL("http://foo"))
				.withKBaseAuthServerURL(new URL("http://bar"))
				.withKBaseUsersGroupID(UUID.fromString(
						"9c72867d-8c90-4f9b-a472-d7759d606471"))
				.withRefreshingToken(rt);
		
		assertThat("correct KBase url", c.getAuthServerURL(), is(new URL("http://bar/")));
		assertThat("correct globus url", c.getGlobusURL(), is(new URL("http://foo/")));
		assertThat("correct group id", c.getKbaseUsersGroupID(),
				is(UUID.fromString("9c72867d-8c90-4f9b-a472-d7759d606471")));
		assertThat("correct token", c.getRefreshingToken(), is(rt));
		assertThat("correct full KBase url", c.getAuthLoginURL(),
				is(new URL("http://bar/Sessions/Login")));
		assertThat("correct full globus url", c.getGlobusGroupMembersURL(),
				is(new URL("http://foo/groups/9c72867d-8c90-4f9b-a472-d7759d606471/members/")));
		
		//urls with trailing slashes
		AuthConfig stdurl = new AuthConfig()
				.withGlobusAuthURL(new URL("http://foo/"))
				.withKBaseAuthServerURL(new URL("http://bar/"));
		
		assertThat("correct KBase url", stdurl.getAuthServerURL(), is(new URL("http://bar/")));
		assertThat("correct globus url", stdurl.getGlobusURL(), is(new URL("http://foo/")));
		
		// setting one token removes the other
		AuthToken t = AuthService.login(TEST_UID, TEST_PW).getToken();
		c.withToken(t);
		assertThat("Didn't remove authtoken", c.getRefreshingToken(),
				is((us.kbase.auth.RefreshingToken) null));
		assertThat("incorrect token", c.getToken(), is (t));
		
		c.withRefreshingToken(rt);
		assertThat("incorrect token", c.getToken(), is (rt.getToken()));
		
		try {
			new AuthConfig().withGlobusAuthURL(null);
			fail("made config with bad args");
		} catch (NullPointerException npe) {
			assertThat("correct exception message", npe.getLocalizedMessage(),
					is("globusAuth cannot be null"));
		}
		
		try {
			new AuthConfig().withKBaseAuthServerURL(null);
			fail("made config with bad args");
		} catch (NullPointerException npe) {
			assertThat("correct exception message", npe.getLocalizedMessage(),
					is("authServer cannot be null"));
		}
		
		try {
			new AuthConfig().withKBaseUsersGroupID(null);
			fail("made config with bad args");
		} catch (NullPointerException npe) {
			assertThat("correct exception message", npe.getLocalizedMessage(),
					is("groupID cannot be null"));
		}
		
		try {
			new AuthConfig().withRefreshingToken(null);
			fail("made config with bad args");
		} catch (NullPointerException npe) {
			assertThat("correct exception message", npe.getLocalizedMessage(),
					is("token cannot be null"));
		}
	}
	
	@Test
	public void configObject() throws Exception {
		
		assertThat("incorrect default auth url",
				AuthConfig.getDefaultAuthURL(),
				is(new URL("https://www.kbase.us/services/authorization/")));
		
		assertThat("incorrect default globus url",
				AuthConfig.getDefaultGlobusURL(),
				is(new URL("https://nexus.api.globusonline.org/")));
		
		try {
			new ConfigurableAuthService(null);
			fail("init auth service with null config");
		} catch (NullPointerException npe) {
			assertThat("correct exception message", npe.getLocalizedMessage(),
					is("config cannot be null"));
		}
		//defaults
		AuthConfig d = new AuthConfig();
		checkDefaultConfig(d);
		AuthConfig d2 = new ConfigurableAuthService(d).getConfig();
		checkDefaultConfig(d2);
		
		
		//custom
		AuthToken t = AuthService.login(TEST_UID, TEST_PW).getToken();
		AuthConfig c = new AuthConfig()
				.withGlobusAuthURL(new URL("https://foo"))
				.withKBaseAuthServerURL(new URL("https://bar"))
				.withKBaseUsersGroupID(UUID.fromString(
						"9c72867d-8c90-4f9b-a472-d7759d606471"))
				.withToken(t);
		
		assertThat("correct KBase url", c.getAuthServerURL(), is(new URL("https://bar/")));
		assertThat("correct globus url", c.getGlobusURL(), is(new URL("https://foo/")));
		assertThat("correct group id", c.getKbaseUsersGroupID(),
				is(UUID.fromString("9c72867d-8c90-4f9b-a472-d7759d606471")));
		assertThat("correct token", c.getToken(), is(t));
		assertThat("correct full KBase url", c.getAuthLoginURL(),
				is(new URL("https://bar/Sessions/Login")));
		assertThat("correct full globus url", c.getGlobusGroupMembersURL(),
				is(new URL("https://foo/groups/9c72867d-8c90-4f9b-a472-d7759d606471/members/")));
		
		// can't set a bogus url when passing the config to the config auth
		// service
		c.withKBaseAuthServerURL(AuthConfig.getDefaultAuthURL());
		AuthConfig c2 = new ConfigurableAuthService(c).getConfig();
		assertThat("correct KBase url", c2.getAuthServerURL(),
				is(new URL("https://www.kbase.us/services/authorization/")));
		assertThat("correct globus url", c2.getGlobusURL(), is(new URL("https://foo/")));
		assertThat("correct group id", c2.getKbaseUsersGroupID(),
				is(UUID.fromString("9c72867d-8c90-4f9b-a472-d7759d606471")));
		assertThat("correct token", c2.getToken(), is(t));
		assertThat("correct full KBase url", c2.getAuthLoginURL(),
				is(new URL("https://www.kbase.us/services/authorization/Sessions/Login")));
		assertThat("correct full globus url", c2.getGlobusGroupMembersURL(),
				is(new URL("https://foo/groups/9c72867d-8c90-4f9b-a472-d7759d606471/members/")));
		
		
		//urls with trailing slashes
		AuthConfig stdurl = new AuthConfig()
				.withGlobusAuthURL(new URL("http://foo/"))
				.withKBaseAuthServerURL(new URL("http://bar/"));
		
		assertThat("correct KBase url", stdurl.getAuthServerURL(), is(new URL("http://bar/")));
		assertThat("correct globus url", stdurl.getGlobusURL(), is(new URL("http://foo/")));
		
		try {
			new AuthConfig().withGlobusAuthURL(null);
			fail("made config with bad args");
		} catch (NullPointerException npe) {
			assertThat("correct exception message", npe.getLocalizedMessage(),
					is("globusAuth cannot be null"));
		}
		
		try {
			new AuthConfig().withKBaseAuthServerURL(null);
			fail("made config with bad args");
		} catch (NullPointerException npe) {
			assertThat("correct exception message", npe.getLocalizedMessage(),
					is("authServer cannot be null"));
		}
		
		try {
			new AuthConfig().withKBaseUsersGroupID(null);
			fail("made config with bad args");
		} catch (NullPointerException npe) {
			assertThat("correct exception message", npe.getLocalizedMessage(),
					is("groupID cannot be null"));
		}
		
		try {
			new AuthConfig().withToken(null);
			fail("made config with bad args");
		} catch (NullPointerException npe) {
			assertThat("correct exception message", npe.getLocalizedMessage(),
					is("token cannot be null"));
		}
	}

	private void checkDefaultConfig(AuthConfig d) throws Exception {
		assertThat("correct KBase url", d.getAuthServerURL(),
				is(new URL("https://www.kbase.us/services/authorization/")));
		assertThat("correct globus url", d.getGlobusURL(),
				is(new URL("https://nexus.api.globusonline.org/")));
		assertThat("correct group id", d.getKbaseUsersGroupID(),
				is(UUID.fromString("99d2a548-7218-11e2-adc0-12313d2d6e7f")));
		assertThat("correct token", d.getToken(), is((AuthToken) null));
		assertThat("correct full KBase url", d.getAuthLoginURL(),
				is(new URL("https://www.kbase.us/services/authorization/Sessions/Login")));
		assertThat("correct full globus url", d.getGlobusGroupMembersURL(),
				is(new URL("https://nexus.api.globusonline.org/groups/99d2a548-7218-11e2-adc0-12313d2d6e7f/members/")));
	}
	
	
	@Test
	public void testGetUserFromTokenObject() throws Exception {
		AuthToken t = new AuthToken(testUser.getToken().getToken(),
				testUser.getUserId());
		AuthUser user = AuthService.getUserFromToken(t);
		org.junit.Assert.assertNotNull("failure - getting user from a token object returned a null user", user);
		
		user = new ConfigurableAuthService().getUserFromToken(t);
		org.junit.Assert.assertNotNull("failure - getting user from a token object returned a null user", user);
	}

	@Test
	public void testLogin() throws Exception {
		AuthUser user = AuthService.login(TEST_UID, TEST_PW);
		org.junit.Assert.assertNotNull("failure - logging in returned a null user", user);
		
		user = new ConfigurableAuthService().login(TEST_UID, TEST_PW);
		org.junit.Assert.assertNotNull("failure - logging in returned a null user", user);
	}
	
	@Test
	public void testValidateToken() throws AuthException, IOException {
		String tokenStr = testUser.getTokenString();
		String tokenStr2 = uncachedTokens.get(0).getToken();
		String tokenStr3 = uncachedTokens.get(1).getToken();
		
		assertThat("token validation failed",
				AuthService.validateToken(tokenStr), is(testUser.getToken()));
		assertThat("token validation failed",
				AuthService.validateToken(tokenStr2),
				is(uncachedTokens.get(0)));
		//tests getting tokens from the cache. Unnoticable other than in
		//coverage report.
		assertThat("token validation failed",
				AuthService.validateToken(tokenStr2),
				is(uncachedTokens.get(0)));
		
		
		assertThat("token validation failed",
				new ConfigurableAuthService().validateToken(tokenStr),
				is(testUser.getToken()));
		assertThat("token validation failed",
				new ConfigurableAuthService().validateToken(tokenStr3),
				is(uncachedTokens.get(1)));
		//tests getting tokens from the cache. Unnoticable other than in
		//coverage report.
		assertThat("token validation failed",
				new ConfigurableAuthService().validateToken(tokenStr3),
				is(uncachedTokens.get(1)));
	}

	// login with bad user/pw
	@Test(expected = AuthException.class)
	public void testFailLogin() throws Exception {
		AuthService.login("asdf", "asdf");
	}
	
	@Test(expected = AuthException.class)
	public void testFailLoginConfigurable() throws Exception {
		new ConfigurableAuthService().login("asdf", "asdf");
	}

	// try to verify a bad token
	@Test(expected = AuthException.class)
	public void testFailValidate() throws AuthException, IOException {
		AuthService.validateToken("asdf");
	}
	
	@Test(expected = AuthException.class)
	public void testFailValidateConfigurable() throws AuthException, IOException {
		new ConfigurableAuthService().validateToken("asdf");
	}

	@Test
	public void testGetUserDetails() throws Exception {
		AuthToken token = testUser.getToken();
		assertThat("no users doesn't return empty hash",
				AuthService.fetchUserDetail(
						new ArrayList<String>(), token).size(), is(0));
		assertThat("no users doesn't return empty hash",
				new ConfigurableAuthService().fetchUserDetail(
						new ArrayList<String>(), token).size(), is(0));
		
		List<String> users = new ArrayList<String>();
		users.add("kbasetest");
		users.add("kbasetest2");
		users.add(null); // should ignore nulls
		users.add("ahfueafavafueafhealuefhalfuafeuauflaef");
		Map<String, UserDetail> res1 =
				AuthService.fetchUserDetail(users, token);
		Map<String, UserDetail> res2 =
				new ConfigurableAuthService().fetchUserDetail(users, token);
		for (Map<String, UserDetail> res: Arrays.asList(res1, res2)) {
			assertFalse("still has a null user", res.containsKey(null));
			assertNull("bad user found somehow", res.get("ahfueafavafueafhealuefhalfuafeuauflaef"));
			UserDetail ud = res.get("kbasetest");
			assertThat("username doesn't match", ud.getUserName(), is("kbasetest"));
			assertThat("email doesn't match", ud.getEmail(), is("kbasetest.globus@gmail.com"));
			assertThat("full name doesn't match", ud.getFullName(), is("KBase Test Account"));
			ud = res.get("kbasetest2");
			assertThat("username doesn't match", ud.getUserName(), is("kbasetest2"));
			assertThat("email doesn't match", ud.getEmail(), is("gaprice@lbl.gov"));
			assertThat("full name doesn't match", ud.getFullName(), is("kbase test account #2"));
			users.remove("kbasetest2");
			users.add("kbasetest8");
		}
		Map<String, Boolean> valid1 =
				AuthService.isValidUserName(users, token);
		Map<String, Boolean> valid2 =
				new ConfigurableAuthService().isValidUserName(users, token);
		
		for (Map<String, Boolean> valid: Arrays.asList(valid1, valid2)) {
			assertThat("validates already seen name", valid.get("kbasetest"), is(true));
			assertThat("validates new name", valid.get("kbasetest8"), is(true));
			assertThat("can't validate bad name", valid.get("ahfueafavafueafhealuefhalfuafeuauflaef"), is(false));
		}
		users.add("\\foo");
		try {
			AuthService.isValidUserName(users, token);
			fail("auth service accepted invalid username");
		} catch (IllegalArgumentException iae) {
			assertThat("incorrect exception message", iae.getLocalizedMessage(),
					is("username \\foo has invalid character: \\"));
		}
		
		try {
			new ConfigurableAuthService().isValidUserName(users, token);
			fail("auth service accepted invalid username");
		} catch (IllegalArgumentException iae) {
			assertThat("incorrect exception message", iae.getLocalizedMessage(),
					is("username \\foo has invalid character: \\"));
		}
	}
	
	//TODO TEST LATER delete this when refreshing tokens are removed
	@SuppressWarnings("deprecation")
	@Test
	public void testGetUserDetailsWithRefreshingToken() throws Exception {
		AuthConfig c = new AuthConfig();
		ConfigurableAuthService cas = new ConfigurableAuthService(c);
		c.withRefreshingToken(cas.getRefreshingToken(TEST_UID, TEST_PW, 10000));
		
		List<String> users = new ArrayList<String>();
		users.add("kbasetest");
		Map<String, UserDetail> res = cas.fetchUserDetail(users);
		UserDetail ud = res.get("kbasetest");
		assertThat("username doesn't match", ud.getUserName(), is("kbasetest"));
		assertThat("email doesn't match", ud.getEmail(), is("kbasetest.globus@gmail.com"));
		assertThat("full name doesn't match", ud.getFullName(), is("KBase Test Account"));
		assertThat("user verifies", cas.isValidUserName(users).get("kbasetest"),
				is(true));
		
		res = cas.fetchUserDetail(users, null);
		ud = res.get("kbasetest");
		assertThat("username doesn't match", ud.getUserName(), is("kbasetest"));
		assertThat("email doesn't match", ud.getEmail(), is("kbasetest.globus@gmail.com"));
		assertThat("full name doesn't match", ud.getFullName(), is("KBase Test Account"));
		assertThat("user verifies", cas.isValidUserName(users, null).get("kbasetest"),
				is(true));
		
		try {
			new ConfigurableAuthService().fetchUserDetail(users);
			fail("got user detail w/o token");
		} catch (TokenException te) {
			assertThat("correct exception message", te.getLocalizedMessage(),
					is("No token specified in the auth client configuration"));
		}
		try {
			new ConfigurableAuthService().fetchUserDetail(users, null);
			fail("got user detail w/o token");
		} catch (NullPointerException npe) {
			assertThat("correct exception message", npe.getLocalizedMessage(),
					is("If no token is specified in the auth client configuration a token must be provided"));
		}
		
		try {
			new ConfigurableAuthService().isValidUserName(users);
			fail("validated user w/o token");
		} catch (TokenException te) {
			assertThat("correct exception message", te.getLocalizedMessage(),
					is("No token specified in the auth client configuration"));
		}
		
		try {
			new ConfigurableAuthService().isValidUserName(users, null);
			fail("validated user w/o token");
		} catch (NullPointerException npe) {
			assertThat("correct exception message", npe.getLocalizedMessage(),
					is("If no token is specified in the auth client configuration a token must be provided"));
		}
	}
	
	@Test
	public void testGetUserDetailsWithConfigToken() throws Exception {
		AuthConfig c = new AuthConfig();
		ConfigurableAuthService cas = new ConfigurableAuthService(c);
		c.withToken(AuthService.login(TEST_UID, TEST_PW).getToken());
		
		List<String> users = new ArrayList<String>();
		users.add("kbasetest");
		Map<String, UserDetail> res = cas.fetchUserDetail(users);
		UserDetail ud = res.get("kbasetest");
		assertThat("username doesn't match", ud.getUserName(), is("kbasetest"));
		assertThat("email doesn't match", ud.getEmail(), is("kbasetest.globus@gmail.com"));
		assertThat("full name doesn't match", ud.getFullName(), is("KBase Test Account"));
		assertThat("user verifies", cas.isValidUserName(users).get("kbasetest"),
				is(true));
		
		res = cas.fetchUserDetail(users, null);
		ud = res.get("kbasetest");
		assertThat("username doesn't match", ud.getUserName(), is("kbasetest"));
		assertThat("email doesn't match", ud.getEmail(), is("kbasetest.globus@gmail.com"));
		assertThat("full name doesn't match", ud.getFullName(), is("KBase Test Account"));
		assertThat("user verifies", cas.isValidUserName(users, null).get("kbasetest"),
				is(true));
		
		try {
			new ConfigurableAuthService().fetchUserDetail(users);
			fail("got user detail w/o token");
		} catch (TokenException te) {
			assertThat("correct exception message", te.getLocalizedMessage(),
					is("No token specified in the auth client configuration"));
		}
		try {
			new ConfigurableAuthService().fetchUserDetail(users, null);
			fail("got user detail w/o token");
		} catch (NullPointerException npe) {
			assertThat("correct exception message", npe.getLocalizedMessage(),
					is("If no token is specified in the auth client configuration a token must be provided"));
		}
		
		try {
			new ConfigurableAuthService().isValidUserName(users);
			fail("validated user w/o token");
		} catch (TokenException te) {
			assertThat("correct exception message", te.getLocalizedMessage(),
					is("No token specified in the auth client configuration"));
		}
		
		try {
			new ConfigurableAuthService().isValidUserName(users, null);
			fail("validated user w/o token");
		} catch (NullPointerException npe) {
			assertThat("correct exception message", npe.getLocalizedMessage(),
					is("If no token is specified in the auth client configuration a token must be provided"));
		}
	}
	
	@Test
	public void throwMangledTokenAtServer() throws Exception {
		try {
			AuthService.validateToken(testUser.getToken() + "a");
		} catch (AuthException ae) {
			assertThat("correct exception message", ae.getLocalizedMessage(),
					is("Login failed! Invalid token"));
		}
		try {
			new ConfigurableAuthService().validateToken(
					testUser.getToken() + "a");
		} catch (AuthException ae) {
			assertThat("correct exception message", ae.getLocalizedMessage(),
					is("Login failed! Invalid token"));
		}
	}
	
	//TODO TEST LATER delete this when refreshing tokens are removed
	@SuppressWarnings("deprecation")
	@Test
	public void refreshToken() throws Exception {
		us.kbase.auth.RefreshingToken rt = AuthService.getRefreshingToken(
				TEST_UID, TEST_PW, 5);
		AuthToken t1 = rt.getToken();
		AuthToken t2 = rt.getToken();
		assertThat("got same token immediately", t2.toString(), is(t1.toString()));
		Thread.sleep(2000); //wait 2s
		AuthToken t3 = rt.getToken();
		assertThat("got same token after 2s", t3.toString(), is(t1.toString()));
		Thread.sleep(4000); //wait 4s
		AuthToken t4 = rt.getToken();
		assertTrue("token different after 6s", !t4.toString().equals(t1.toString()));
		
		rt = new ConfigurableAuthService().getRefreshingToken(
				TEST_UID, TEST_PW, 5);
		t1 = rt.getToken();
		t2 = rt.getToken();
		assertThat("got same token immediately", t2.toString(), is(t1.toString()));
		Thread.sleep(2000); //wait 2s
		t3 = rt.getToken();
		assertThat("got same token after 2s", t3.toString(), is(t1.toString()));
		Thread.sleep(4000); //wait 4s
		t4 = rt.getToken();
		assertTrue("token different after 6s", !t4.toString().equals(t1.toString()));
	}
	
	//TODO TEST LATER delete this when refreshing tokens are removed
	@Test
	public void refreshTokenWithBadArgs() throws Exception {
		failMakeRefreshToken(TEST_UID, TEST_PW, -1,
				new IllegalArgumentException(
						"refreshInterval must be 0 or greater"));
		failMakeRefreshToken(null, TEST_PW, 0,
				new IllegalArgumentException(
						"user cannot be null or the empty string"));
		failMakeRefreshToken("", TEST_PW, 0,
				new IllegalArgumentException(
						"user cannot be null or the empty string"));
		failMakeRefreshToken(TEST_UID, null, 0,
				new IllegalArgumentException(
						"password cannot be null or the empty string"));
		failMakeRefreshToken(TEST_UID, "", 0,
				new IllegalArgumentException(
						"password cannot be null or the empty string"));
		
	}

	//TODO TEST LATER delete this when refreshing tokens are removed
	@SuppressWarnings("deprecation")
	private void failMakeRefreshToken(String testUid, String testPw,
			int interval, Exception expected) {
		try {
			AuthService.getRefreshingToken(testUid, testPw, interval);
			fail("Made refreshing token with bad args");
		} catch (Exception got) {
			assertThat("correct exception", got.getLocalizedMessage(),
					is(expected.getLocalizedMessage()));
			assertThat("correct exception type", got, is(expected.getClass()));
		}
		
		try {
			new ConfigurableAuthService().getRefreshingToken(testUid, testPw, interval);
			fail("Made refreshing token with bad args");
		} catch (Exception got) {
			assertThat("correct exception", got.getLocalizedMessage(),
					is(expected.getLocalizedMessage()));
			assertThat("correct exception type", got, is(expected.getClass()));
		}
	}
	
	// finished with AuthService methods
}

