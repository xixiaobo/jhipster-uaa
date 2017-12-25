package com.hcycom.jhipster.domain;

public class Group {
	private String uuid;
	private String group_name;
	private String group_desc;
	private int group_super;
	private int group_type;
	private int group_status;
	public String getUuid() {
		return uuid;
	}
	public void setUuid(String uuid) {
		this.uuid = uuid;
	}
	public String getGroup_name() {
		return group_name;
	}
	public void setGroup_name(String group_name) {
		this.group_name = group_name;
	}
	public String getGroup_desc() {
		return group_desc;
	}
	public void setGroup_desc(String group_desc) {
		this.group_desc = group_desc;
	}
	public int getGroup_super() {
		return group_super;
	}
	public void setGroup_super(int group_super) {
		this.group_super = group_super;
	}
	public int getGroup_type() {
		return group_type;
	}
	public void setGroup_type(int group_type) {
		this.group_type = group_type;
	}
	public int getGroup_status() {
		return group_status;
	}
	public void setGroup_status(int group_status) {
		this.group_status = group_status;
	}
	@Override
	public String toString() {
		return "Group [uuid=" + uuid + ", group_name=" + group_name + ", group_desc=" + group_desc + ", group_super="
				+ group_super + ", group_type=" + group_type + ", group_status=" + group_status + "]";
	}
	
}
