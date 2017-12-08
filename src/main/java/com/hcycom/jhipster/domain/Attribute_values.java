package com.hcycom.jhipster.domain;

/**
 * 属性值表实体类
 * 
 * @author Xi
 *
 */
public class Attribute_values {
	private String uuid; // uuid
	private String resource_name; // 资源名称
	private String attribute_key; // 属性key
	private String value; // 属性值

	public String getUuid() {
		return uuid;
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public String getResource_name() {
		return resource_name;
	}

	public void setResource_name(String resource_name) {
		this.resource_name = resource_name;
	}

	public String getAttribute_key() {
		return attribute_key;
	}

	public void setAttribute_key(String attribute_key) {
		this.attribute_key = attribute_key;
	}

	
	

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	@Override
	public String toString() {
		return "Attribute_values [uuid=" + uuid + ", resource_name=" + resource_name + ", attribute_key="
				+ attribute_key + ", value=" + value + "]";
	}

}
