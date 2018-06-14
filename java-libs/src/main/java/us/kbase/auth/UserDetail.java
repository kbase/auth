package us.kbase.auth;

/**
 * Details for an unauthenticated user.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class UserDetail {
//	private boolean emailValidated = false;
	private String username = null;
	private String email = null;
	private String fullname = null;

	public UserDetail(String username, String email, String fullname) {
		this.username = username;
		this.email = email;
		this.fullname = fullname;
	}

	public String getUserName() {
		return username;
	}
	
	public String getEmail() {
		return email;
	}

	public String getFullName() {
		return fullname;
	}

	@Override
	public String toString() {
		return "UserDetail [username=" + username + ", email=" + email
				+ ", fullname=" + fullname + "]";
	}
}