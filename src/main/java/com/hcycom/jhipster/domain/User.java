package com.hcycom.jhipster.domain;

import java.util.HashSet;
import java.util.Set;

/**
 * 用户实体类
 * 
 * @author Xi
 *
 */
public class User {

	private String id;
	private String username;
	private String name_cn;
	private String head_image;
	private String email;
	private String phone;
	private String sex;
	private int status;
	private String groups;
	private String roles;
	private String password;
	private String login;
	private Set<String> authorities = new HashSet<>();

	
	public String getLogin() {
		return login;
	}

	public void setLogin(String login) {
		this.login = login;
	}

	
	public Set<String> getAuthorities() {
		return authorities;
	}

	public void setAuthorities(Set<String> authorities) {
		this.authorities = authorities;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getName_cn() {
		return name_cn;
	}

	public void setName_cn(String name_cn) {
		this.name_cn = name_cn;
	}

	public String getHead_image() {
		return head_image;
	}

	public void setHead_image(String head_image) {
		this.head_image = head_image;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPhone() {
		return phone;
	}

	public void setPhone(String phone) {
		this.phone = phone;
	}

	public String getSex() {
		return sex;
	}

	public void setSex(String sex) {
		this.sex = sex;
	}

	public int getStatus() {
		return status;
	}

	public void setStatus(int status) {
		this.status = status;
	}

	public String getGroups() {
		return groups;
	}

	public void setGroups(String groups) {
		this.groups = groups;
	}

	public String getRoles() {
		return roles;
	}

	public void setRoles(String roles) {
		this.roles = roles;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@Override
	public String toString() {
		return "Users [id=" + id + ", username=" + username + ", name_cn=" + name_cn + ", head_image=" + head_image
				+ ", email=" + email + ", phone=" + phone + ", sex=" + sex + ", status=" + status + ", groups=" + groups
				+ ", roles=" + roles + ", password=" + password + "]";
	}

}
