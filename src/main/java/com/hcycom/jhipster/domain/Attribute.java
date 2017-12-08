package com.hcycom.jhipster.domain;

/**
 * 属性表实体类
 * @author Xi
 *
 */
public class Attribute {
	private String attribute_key;	//属性key，主键，唯一
	private String attribute_name;	//属性名称
	private String attribute_type;	//属性值类型(字符，日期，数字，布尔，枚举，外键)
	private String format_str;	//属性格式化字符串
	private int is_delete;	//是否可以删除（0：是；1：否）
	private int is_enable;	//是否在页面显示（0：是；1：否）
	private int attribute_status;	//是否在页面显示（0：启用；1：禁用）
	private int order;	//显示顺序
	private String resource_name_foreign;	//外键资源名称
	public String getAttribute_key() {
		return attribute_key;
	}
	public void setAttribute_key(String attribute_key) {
		this.attribute_key = attribute_key;
	}
	public String getAttribute_name() {
		return attribute_name;
	}
	public void setAttribute_name(String attribute_name) {
		this.attribute_name = attribute_name;
	}
	public String getAttribute_type() {
		return attribute_type;
	}
	public void setAttribute_type(String attribute_type) {
		this.attribute_type = attribute_type;
	}
	public String getFormat_str() {
		return format_str;
	}
	public void setFormat_str(String format_str) {
		this.format_str = format_str;
	}
	public int getIs_delete() {
		return is_delete;
	}
	public void setIs_delete(int is_delete) {
		this.is_delete = is_delete;
	}
	public int getIs_enable() {
		return is_enable;
	}
	public void setIs_enable(int is_enable) {
		this.is_enable = is_enable;
	}
	public int getAttribute_status() {
		return attribute_status;
	}
	public void setAttribute_status(int attribute_status) {
		this.attribute_status = attribute_status;
	}
	
	public int getOrder() {
		return order;
	}
	public void setOrder(int order) {
		this.order = order;
	}
	public String getResource_name_foreign() {
		return resource_name_foreign;
	}
	public void setResource_name_foreign(String resource_name_foreign) {
		this.resource_name_foreign = resource_name_foreign;
	}
	@Override
	public String toString() {
		return "Attribute [attribute_key=" + attribute_key + ", attribute_name=" + attribute_name + ", attribute_type="
				+ attribute_type + ", format_str=" + format_str + ", is_delete=" + is_delete + ", is_enable="
				+ is_enable + ", attribute_status=" + attribute_status + ", order=" + order + ", resource_name_foreign="
				+ resource_name_foreign + "]";
	}
	
}
