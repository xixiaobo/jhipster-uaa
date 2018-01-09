package com.hcycom.jhipster.service.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface InterfacePermissionsMapper {
	
	@Select("SELECT role_name FROM role WHERE uuid in (SELECT role_uuid FROM role_authority WHERE authority_uuid=(SELECT uuid FROM authority WHERE authority_type=4 and authority_status=1 and authority_url=#{authority_url}))")
	public List<String> getRoleByProduct(@Param("authority_url")String authority_url);

}
