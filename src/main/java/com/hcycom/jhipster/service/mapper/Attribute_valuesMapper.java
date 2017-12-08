package com.hcycom.jhipster.service.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

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
	@Insert("INSERT INTO attribute_values VALUES " + "(#{attribute_values.uuid},#{attribute_values.resource_name},"
			+ "#{attribute_values.attribute_key},#{attribute_values.value})")
	public int addAttribute_values(@Param("attribute_values") Attribute_values attribute_values);

	/**
	 * 删除资源数据记录，如果uuid值为空，则删除该资源所有属性
	 * 
	 * @param attribute
	 * @return
	 */
	@Delete({ "<script>", "DELETE FROM attribute_values", "WHERE resource_name=#{attribute_values.resource_name}",
			"<if test=\"#{attribute_values.uuid} != null \">", "AND uuid = #{attribute_values.uuid}", "</if>",
			"</script>" })
	public int deleteAttribute_values(@Param("attribute_values") Attribute_values attribute_values);

	/**
	 * 修改资源数据记录
	 * 
	 * @param attribute
	 * @return
	 */
	@Update("update attribute_values set " + "value = #{attribute_values.value}"
			+ "where attribute_key=#{attribute_values.attribute_key} and resource_name=#{attribute_values.resource_name} AND uuid = #{attribute_values.uuid} ")
	public int updateAttribute_values(@Param("attribute_values") Attribute_values attribute_values);

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
	 * 根据用户名查找用户
	 * 
	 * @param resource_name
	 * @param username
	 * @return
	 */
	@Select("SELECT	* " + "FROM attribute_values WHERE resource_name = #{resource_name} and " + "uuid in "
			+ "( SELECT uuid " + "FROM attribute_values WHERE " + "attribute_key = 'username' AND value = #{username})")
	public List<Attribute_values> findUserByName(@Param("resource_name") String resource_name,
			@Param("username") String username);

	/**
	 * 查询所有资源
	 * 
	 * @return
	 */
	@Select("select * from attribute_values")
	public List<Attribute_values> findAttribute_valuesAll();

}
