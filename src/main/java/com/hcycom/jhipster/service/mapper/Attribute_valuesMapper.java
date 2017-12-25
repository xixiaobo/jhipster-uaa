package com.hcycom.jhipster.service.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;
import org.springframework.data.domain.Pageable;

import com.hcycom.jhipster.domain.Attribute_values;

/**
 * mybatis的属性值表管理mapper
 * 
 * @author Xi
 *
 */
@Mapper
public interface Attribute_valuesMapper {

	/**
	 * 添加资源数据记录
	 * 
	 * @param attribute
	 * @return
	 */
	@Insert("INSERT INTO attribute_values VALUES (#{attribute_values.uuid},#{attribute_values.resource_name},"
			+ "#{attribute_values.attribute_key},#{attribute_values.value})")
	public int addAttribute_values(@Param("attribute_values") Attribute_values attribute_values);

	/**
	 * 删除指定uuid和资源名称的资源数据记录
	 * 
	 * @param attribute
	 * @return
	 */
	@Delete("DELETE FROM attribute_values WHERE resource_name=#{attribute_values.resource_name}"
			+ "AND uuid = #{attribute_values.uuid}")
	public int deleteAttribute_valuesByResource_nameAndUuid(
			@Param("attribute_values") Attribute_values attribute_values);

	/**
	 * 删除指定资源名称的所有资源数据记录
	 * 
	 * @param attribute
	 * @return
	 */
	@Delete("DELETE FROM attribute_values WHERE resource_name=#{attribute_values.resource_name}")
	public int deleteAttribute_valuesByResource_name(@Param("attribute_values") Attribute_values attribute_values);

	/**
	 * 删除指定 属性key和资源名称的资源数据记录
	 * 
	 * @param attribute
	 * @return
	 */
	@Delete("DELETE FROM attribute_values WHERE resource_name=#{attribute_values.resource_name}"
			+ "AND attribute_key = #{attribute_values.attribute_key}")
	public int deleteAttribute_valuesByResource_nameAndAttribute_key(
			@Param("attribute_values") Attribute_values attribute_values);
	
	/**
	 *根据UUID以及属性key删除资源数据记录
	 * 
	 * @param attribute
	 * @return
	 */
	@Delete("DELETE FROM attribute_values WHERE resource_name=#{attribute_values.resource_name}"
			+ "AND attribute_key = #{attribute_values.attribute_key} AND uuid = #{attribute_values.uuid}")
	public int deleteAttribute_valuesByOnly(
			@Param("attribute_values") Attribute_values attribute_values);
	
	/**
	 * 删除所有指定属性key的属性值
	 * @param Listkey
	 * @param resource_name
	 * @return
	 */
	@Delete("DELETE FROM attribute_values where resource_name=#{resource_name} AND attribute_key in (#{Listkey})")
	public int deleteAttribute_valuesByResource_nameNolimit(@Param("Listkey") String Listkey,
			@Param("resource_name") String resource_name);
	
	

	/**
	 * 修改资源数据记录
	 * 
	 * @param attribute
	 * @return
	 */
	@Update("update attribute_values set value = #{attribute_values.value}"
			+ "where attribute_key=#{attribute_values.attribute_key} and resource_name=#{attribute_values.resource_name} AND uuid = #{attribute_values.uuid} ")
	public int updateAttribute_values(@Param("attribute_values") Attribute_values attribute_values);

	/**
	 * 使用REPLACE更新字段
	 * 
	 * @param attribute_values
	 * @return
	 */
	@Update("update attribute_values set value=replace(value,'${attribute_values.value}','') "
			+ "where attribute_key=#{attribute_values.attribute_key} "
			+ "and resource_name=#{attribute_values.resource_name} AND value like '${attribute_values.value}'")
	public int replaceUpdateAttribute_values(@Param("attribute_values") Attribute_values attribute_values);

	/**
	 * 根据资源名和uuid查询资源数据记录
	 * 
	 * @param attribute
	 * @return
	 */
	@Select("select * from attribute_values WHERE resource_name=#{attribute_values.resource_name} AND uuid = #{attribute_values.uuid}")
	public List<Attribute_values> findAttribute_valuesByResource_nameANDUuid(
			@Param("attribute_values") Attribute_values attribute_values);

	/**
	 * 根据资源名查询资源属性返回该资源的所有属性值
	 * 
	 * @param attribute
	 * @return
	 */
	@Select("select * from attribute_values WHERE resource_name=#{attribute_values.resource_name}")
	public List<Attribute_values> findAttribute_valuesByResource_name(
			@Param("attribute_values") Attribute_values attribute_values);

	/**
	 * 根据资源名和key查询资源数据记录
	 * 
	 * @param attribute
	 * @return
	 */
	@Select("select * from attribute_values WHERE resource_name=#{attribute_values.resource_name} AND attribute_key = #{attribute_values.attribute_key}")
	public List<Attribute_values> findAttribute_valuesByResource_nameANDKey(
			@Param("attribute_values") Attribute_values attribute_values);

	/**
	 * 根据用户名查找用户
	 * 
	 * @param resource_name
	 * @param username
	 * @return
	 */
	@Select("SELECT	* FROM attribute_values WHERE resource_name = #{resource_name} and uuid in "
			+ "( SELECT uuid FROM attribute_values WHERE attribute_key = 'username' AND value = #{username})")
	public List<Attribute_values> findUserByName(@Param("resource_name") String resource_name,
			@Param("username") String username);

	/**
	 * 根据分页查找用户id
	 * 
	 * @param pageable
	 * @param resource_name
	 * @return
	 */
	@Select("select uuid from attribute_values " + "WHERE resource_name=#{resource_name} and attribute_key = 'id' "
			+ "limit ${pageable.offset}, ${pageable.pageSize}")
	public List<String> findAttribute_valuesByPage(@Param("pageable") Pageable pageable,
			@Param("resource_name") String resource_name);

	/**
	 * 查询所有资源
	 * 
	 * @return
	 */
	@Select("select * from attribute_values")
	public List<Attribute_values> findAttribute_valuesAll();

	/**
	 * 根据用户名查找用户id
	 * 
	 * @param resource_name
	 * @param value
	 * @return
	 */
	@Select("select * from attribute_values WHERE resource_name=#{resource_name} AND attribute_key = 'username' and value= #{value}")
	public Attribute_values findIdByName(@Param("resource_name") String resource_name, @Param("value") String value);

	/**
	 * 根据用户id集合获取用户详情
	 * 
	 * @param listID
	 * @param string
	 * @return
	 */
	@Select("select * from attribute_values where resource_name=#{resource_name} AND uuid in (#{listID})")
	public List<Attribute_values> findAttribute_valuesByListID(@Param("listID") String listID,
			@Param("resource_name") String resource_name);

	/**
	 * 根据条件检索值
	 * 
	 * @param attribute_values
	 * @param sql
	 * @return
	 */
	@Select("select * from attribute_values where resource_name=#{attribute_values.resource_name} "
			+ "AND attribute_key =#{attribute_values.attribute_key} and value like #{sql}")
	public List<String> findAttribute_valuesByKeyAndValue(@Param("attribute_values") Attribute_values attribute_values,
			@Param("sql") String sql);

}
