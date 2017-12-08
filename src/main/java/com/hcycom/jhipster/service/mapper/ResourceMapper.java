package com.hcycom.jhipster.service.mapper;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import com.hcycom.jhipster.domain.Resource;

/**
 * mybatis的资源表管理mapper
 * @author Xi
 *
 */
@Mapper
public interface ResourceMapper {

	@Insert("INSERT INTO resource VALUES "
			+ "(#{resource.resource_name},#{resource.visible_name},#{resource.resource_desc},"
			+ "#{resource.is_delete},#{resource.save_table})")
	public int addResource(@Param("resource")Resource resource);

	@Update("update resource set "
			+ "visible_name = #{resource.visible_name} ,"
			+ "resource_desc = #{resource.resource_desc} ,"
			+ "is_delete = #{resource.is_delete} ,"
			+ "save_table = #{resource.save_table}"
			+ "where resource_name = #{resource.resource_name} ")
	public int updateResource(@Param("resource")Resource resource);
	
	@Delete("DELETE FROM resource where resource_name = #{resource.resource_name} ")
	public int deleteResource(@Param("resource")Resource resource);
	
	@Select("select * from resource where resource_name = #{resource_name}")
	public Resource findResoureByResource_name(@Param("resource_name")String resource_name);
	
	/**
	 * 根据save_table值查询资源
	 * @param save_table
	 * @return
	 */
	@Select("select * from resource where save_table = #{save_table}")
	public Resource findResoureBySave_table(@Param("save_table")String save_table);
	

}
