package com.hcycom.jhipster.service.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import com.hcycom.jhipster.domain.Role;

@Mapper
public interface ProductMapper {
	
	@Select("SELECT role_name FROM role WHERE uuid on (SELECT role_uuid FROM role_authority WHERE authority_uuid=(SELECT uuid FROM authority WHERE authority_type=4 and authority_status=1 and authority_url=#{authority_url}))")
	public List<String> getRoleByProduct(String authority_url);

}
