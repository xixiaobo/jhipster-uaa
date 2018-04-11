package com.hcycom.jhipster.service.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import com.hcycom.jhipster.domain.Authority;


@Mapper
public interface AuthorityMapper {
	
	
	/**
	 * 添加权限
	 * 
	 * @param product
	 * @return
	 */
	@Insert("INSERT INTO authority(uuid,authority_name,authority_type,foreign_uuid,authority_url,authority_status) VALUES "
			+ "(#{authority.uuid},#{authority.authority_name},#{authority.authority_type},"
			+ "#{authority.foreign_uuid},#{authority.authority_url},#{authority.authority_url},#{authority.authority_status})")
	public int addInterfaceAuthority(@Param("authority") Authority authority);
	

	@Delete("DELETE a, r FROM	authority a LEFT JOIN role_authority r ON a.uuid = r.authority_uuid WHERE a.uuid=#{authuuid}")
	public int deleteInterfaceAuthority(@Param("authuuid") String authuuid);
	
	
	/**
	 * 根据uuid获取权限信息
	 * @param uuid
	 * @return
	 */
	@Select("select * from authority where uuid=#{uuid}")
	public Authority getAuthorityByUuid(@Param("uuid")String uuid);
	/**
	 * 根据权限类型获取权限
	 * @return
	 */
	@Select("select * from authority where authority_type=#{authority_type}")
	public List<Authority> getAllAuthorityByAuthority_type(String authority_type);
	/**
	 * 获取所有的权限
	 * @return
	 */
	@Select("select * from authority")
	public List<Authority> getAllAuthority();
	
	/**
	 * 根据权限名称模糊查找权限
	 * @param authority_name
	 * @return
	 */
	@Select("select * from authority where authority_name COLLATE utf8_general_ci like #{authority_name}")
	public List<Authority> getAllAuthorityByLike(@Param("authority_name")String authority_name);

	/**
	 * 根据权限类型以及权限名称模糊查找权限
	 * @param authority_name
	 * @return
	 */
	@Select("select * from authority "
			+ "where authority_type=#{authority_type}"
			+ "and authority_name COLLATE utf8_general_ci like #{authority_name}")
	public List<Authority> getAuthorityByLike(@Param("authority_name")String authority_name,@Param("authority_type") String authority_type);
	
}
