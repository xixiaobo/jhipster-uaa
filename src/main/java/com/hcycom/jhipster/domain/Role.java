package com.hcycom.jhipster.domain;

public class Role {
	
	private int uuid;
	private String role_name;
	private String role_desc;
	public int getUuid() {
		return uuid;
	}
	public void setUuid(int uuid) {
		this.uuid = uuid;
	}
	public String getRole_name() {
		return role_name;
	}
	public void setRole_name(String role_name) {
		this.role_name = role_name;
	}
	public String getRole_desc() {
		return role_desc;
	}
	public void setRole_desc(String role_desc) {
		this.role_desc = role_desc;
	}
	@Override
	public String toString() {
		return "Role [uuid=" + uuid + ", role_name=" + role_name + ", role_desc=" + role_desc + "]";
	}

	

}
