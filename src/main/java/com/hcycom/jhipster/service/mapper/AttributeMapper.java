package com.hcycom.jhipster.service.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import com.hcycom.jhipster.domain.Attribute;

/**
 * mybatis的属性表管理mapper
 * @author Xi
 *
 */
@Mapper
public interface AttributeMapper {
	

	/**
	 * 添加资源属性
	 * @param attribute
	 * @return
	 */
	@Insert("INSERT INTO attribute VALUES "
			+ "(#{attribute.attribute_key},#{attribute.attribute_name},"
			+ "#{attribute.attribute_type},#{attribute.format_str},"
			+ "#{attribute.is_delete},#{attribute.is_enable},"
			+ "#{attribute.attribute_status},#{attribute.order},"
			+ "#{attribute.resource_name},#{attribute.resource_name_foreign}")
	public int addAttribute(@Param("attribute")Attribute attribute);
	
	/**
	 * 删除指定属性key和资源名称的资源属性
	 * @param attribute
	 * @return
	 */
	@Delete("DELETE FROM attribute WHERE resource_name=#{attribute.resource_name} "
			+ "AND attribute_key = #{attribute.attribute_key}  and is_delete=0")
	public int deleteAttributeByResource_nameAndAttribute_key(@Param("attribute")Attribute attribute);
	
	/**
	 * 删除指定的资源名称下所有可以删除的资源属性
	 * @param attribute
	 * @return
	 */
	@Delete("DELETE FROM attribute WHERE resource_name=#{attribute.resource_name} and is_delete=0 ")
	public int deleteAttributeByResource_nameLimit(@Param("attribute")Attribute attribute);
	
	/**
	 * 直接删除指定的资源名称下所有资源属性
	 * @param attribute
	 * @return
	 */
	@Delete("DELETE FROM attribute WHERE resource_name=#{attribute.resource_name} ")
	public int deleteAttributeByResource_nameNoLimit(@Param("attribute")Attribute attribute);
	
	/**
	 * 修改资源属性
	 * @param attribute
	 * @return
	 */
	@Update("update attribute set "
			+ "attribute_name = #{attribute.attribute_name},"
			+ "attribute_type = #{attribute.attribute_type},"
			+ "format_str = #{attribute.format_str},"
			+ "is_enable = #{attribute.is_enable},"
			+ "attribute_status = #{attribute.attribute_status},"
			+ "order = #{attribute.order},"
			+ "resource_name_foreign = #{attribute.resource_name_foreign}"
			+ "where attribute_key = #{attribute.attribute_key} and resource_name = #{attribute.resource_name}")
	public int updateAttribute(@Param("attribute")Attribute attribute);
	
	/**
	 * 根据资源名查询资源属性，如果attribute_key为空，则返回该资源所有属性
	 * @param attribute
	 * @return
	 */
	@Select("select * from attribute WHERE resource_name_foreign=#{attribute.resource_name_foreign} AND attribute_key = #{attribute.attribute_key}")
	public Attribute findAttributeByResource_nameAndAttribute_key(@Param("attribute")Attribute attribute);
	

	/**
	 * 根据资源名查询并按照order排序
	 * @param attribute
	 * @return
	 */
	@Select("select * from attribute WHERE resource_name_foreign=#{attribute.resource_name_foreign} ORDER BY `order`")
	public List<Attribute> findAttributeByResource_name(@Param("attribute")Attribute attribute);
	
	/**
	 * 根据资源名查询所有可以删除的属性
	 * @param attribute
	 * @return
	 */
	@Select("select attribute_key from attribute WHERE resource_name_foreign=#{attribute.resource_name_foreign} and is_delete=0")
	public List<String> findAttributeByResource_nameNoLimit(@Param("attribute")Attribute attribute);
	
	/**
	 * 查询所有资源
	 * @return
	 */
	@Select("select * from attribute")
	public List<Attribute> findAttributeAll();
}
