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
			+ "#{attribute.resource_name_foreign}")
	public int addAttribute(@Param("attribute")Attribute attribute);
	
	/**
	 * 删除资源属性，如果attribute_key值为空，则删除该资源所有属性
	 * @param attribute
	 * @return
	 */
	@Delete({"<script>",
    "DELETE FROM attribute",
    "WHERE resource_name=#{attribute.resource_name}",
    "<if test=\"#{attribute.attribute_key} != null \">",
    "AND attribute_key = #{attribute.attribute_key}",
    "</if>",
    "</script>"})
	public int deleteAttribute(@Param("attribute")Attribute attribute);
	
	/**
	 * 修改资源属性
	 * @param attribute
	 * @return
	 */
	@Update("update attribute set "
			+ "attribute_key = #{attribute.attribute_key} ,"
			+ "attribute_name = #{attribute.attribute_name},"
			+ "attribute_type = #{attribute.attribute_type},"
			+ "format_str = #{attribute.format_str},"
			+ "is_delete = #{attribute.is_delete},"
			+ "is_enable = #{attribute.is_enable},"
			+ "attribute_status = #{attribute.attribute_status},"
			+ "order = #{attribute.order},"
			+ "resource_name_foreign = #{attribute.resource_name_foreign}"
			+ "where attribute_key = #{attribute.attribute_key} and resource_name_foreign = #{attribute.resource_name_foreign}")
	public int updateAttribute(@Param("attribute")Attribute attribute);
	
	/**
	 * 根据资源名查询资源属性，如果attribute_key为空，则返回该资源所有属性
	 * @param attribute
	 * @return
	 */
	@Select("select * from attribute WHERE resource_name_foreign=#{attribute.resource_name_foreign} AND attribute_key = #{attribute.attribute_key}")
	public Attribute findAttributeByResource_nameAndAttribute_key(@Param("attribute")Attribute attribute);
	

	@Select("select * from attribute WHERE resource_name_foreign=#{attribute.resource_name_foreign}")
	public List<Attribute> findAttributeByResource_name(@Param("attribute")Attribute attribute);
	
	/**
	 * 查询所有资源
	 * @return
	 */
	@Select("select * from attribute")
	public List<Attribute> findAttributeAll();
}
