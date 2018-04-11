package com.hcycom.jhipster.domain;

public class Role_authority {
	private int uuid;
	private String role_uuid;
	private String authority_uuid;
	private String authority_type;
	public int getUuid() {
		return uuid;
	}
	public void setUuid(int uuid) {
		this.uuid = uuid;
	}
	
	public String getRole_uuid() {
		return role_uuid;
	}
	public void setRole_uuid(String role_uuid) {
		this.role_uuid = role_uuid;
	}
	public String getAuthority_uuid() {
		return authority_uuid;
	}
	public void setAuthority_uuid(String authority_uuid) {
		this.authority_uuid = authority_uuid;
	}
	
	public String getAuthority_type() {
		return authority_type;
	}
	public void setAuthority_type(String authority_type) {
		this.authority_type = authority_type;
	}
	@Override
	public String toString() {
		return "Role_authority [uuid=" + uuid + ", role_uuid=" + role_uuid + ", authority_uuid=" + authority_uuid
				+ ", authority_type=" + authority_type + "]";
	}
	
}
