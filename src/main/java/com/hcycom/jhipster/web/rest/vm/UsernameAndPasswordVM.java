package com.hcycom.jhipster.web.rest.vm;

/**
 * View Model object for storing the user's key and password.
 */
public class UsernameAndPasswordVM {

    private String username;

    private String newPassword;

   

    public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
