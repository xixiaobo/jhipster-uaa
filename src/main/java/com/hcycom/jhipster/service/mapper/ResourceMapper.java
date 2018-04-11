package com.hcycom.jhipster.service.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import com.hcycom.jhipster.domain.Resource;

/**
 * mybatis的资源表管理mapper
 * 
 * @author Xi
 *
 */
@Mapper
public interface ResourceMapper {

	/**
	 * 添加资源
	 * 
	 * @param resource
	 * @return
	 */
	@Insert("INSERT INTO resource VALUES "
			+ "(#{resource.resource_name},#{resource.visible_name},#{resource.resource_desc},"
			+ "#{resource.is_delete},#{resource.save_table})")
	public int addResource(@Param("resource") Resource resource);
	
	@Select("select TABLE_NAME from INFORMATION_SCHEMA.TABLES where TABLE_SCHEMA='Ntopia' and TABLE_NAME=#{resource.save_table}")
	public String findTable(@Param("resource") Resource resource);
	
	@Update("CREATE TABLE `${resource.save_table}` ( "
			+ "`uuid` varchar(32) COLLATE utf8_bin NOT NULL COMMENT ' uuid ',"
			+ "`resource_name` varchar(45) COLLATE utf8_bin DEFAULT NULL COMMENT '资源名称',"
			+ "`attribute_key` varchar(128) COLLATE utf8_bin DEFAULT NULL COMMENT '属性key',"
			+ "`value` longtext COLLATE utf8_bin DEFAULT NULL COMMENT ' 属性值'"
			+ ") ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;")
	public int addResourceTable(@Param("resource") Resource resource);

	/**
	 * 修改资源
	 * 
	 * @param resource
	 * @return
	 */
	@Update("update resource set visible_name = #{resource.visible_name} ,"
			+ "resource_desc = #{resource.resource_desc} , is_delete = #{resource.is_delete} where resource_name = #{resource.resource_name} ")
	public int updateResource(@Param("resource") Resource resource);

	/**
	 * 根据资源名称删除可删除选项的资源
	 * @param resource
	 * @return
	 */
	@Delete("DELETE FROM resource where resource_name = #{resource.resource_name}  and is_delete=0")
	public int deleteResource(@Param("resource") Resource resource);
	@Select("select resource_name from resource where save_table = #{resource.save_table}")
	public List<String> findOtherTable(@Param("resource") Resource resource);
	@Delete("DROP TABLE IF EXISTS `${resource.save_table}`")
	public int deleteResourceTable(@Param("resource") Resource resource);

	/**
	 * 根据资源名称查找资源
	 * @param resource_name
	 * @return
	 */
	@Select("select * from resource where resource_name = #{resource_name}")
	public Resource findResoureByResource_name(@Param("resource_name") String resource_name);

	/**
	 * 根据save_table值查询资源
	 * 
	 * @param save_table
	 * @return
	 */
	@Select("select * from resource where save_table = #{save_table}")
	public Resource findResoureBySave_table(@Param("save_table") String save_table);

	/**
	 * 查询所有资源
	 * 
	 * @param save_table
	 * @return
	 */
	@Select("select * from resource")
	public List<Resource> findResoureAll();

}
