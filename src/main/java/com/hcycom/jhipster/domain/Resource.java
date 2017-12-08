package com.hcycom.jhipster.domain;

/**
 * 资源表实体类
 * @author Xi
 *
 */
public class Resource {
	private String resource_name;	//资源名称，主键，唯一
	private String visible_name;	//资源名称别名
	private String resource_desc;	//资源描述
	private int is_delete;	//是否可删除（0：’是’；1：’否’）
	private String save_table;	//存储表名称
	public String getResource_name() {
		return resource_name;
	}
	public void setResource_name(String resource_name) {
		this.resource_name = resource_name;
	}
	public String getVisible_name() {
		return visible_name;
	}
	public void setVisible_name(String visible_name) {
		this.visible_name = visible_name;
	}
	public String getResource_desc() {
		return resource_desc;
	}
	public void setResource_desc(String resource_desc) {
		this.resource_desc = resource_desc;
	}
	public int getIs_delete() {
		return is_delete;
	}
	public void setIs_delete(int is_delete) {
		this.is_delete = is_delete;
	}
	public String getSave_table() {
		return save_table;
	}
	public void setSave_table(String save_table) {
		this.save_table = save_table;
	}
	@Override
	public String toString() {
		return "Resource [resource_name=" + resource_name + ", visible_name=" + visible_name + ", resource_desc="
				+ resource_desc + ", is_delete=" + is_delete + ", save_table=" + save_table + "]";
	}
	

}
