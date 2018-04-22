package com.hcycom.jhipster.web.rest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.codahale.metrics.annotation.Timed;
import com.hcycom.jhipster.domain.Authority;
import com.hcycom.jhipster.service.mapper.AuthorityMapper;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

/**
 * 资源管理接口
 * 
 * @author Xi
 *
 */
@RestController
@RequestMapping("/api")
@Api(tags = { "权限管理" }, description = "权限管理接口")
public class AuthorityController {
	private final Logger log = LoggerFactory.getLogger(AuthorityController.class);


	@Autowired
	private AuthorityMapper authorityMapper;
	
	@RequestMapping(value = "/InterfaceAuthority", method = RequestMethod.POST)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/InterfaceAuthority--POST')")
	@ApiOperation(value = "添加接口权限", notes = "添加接口权限记录", httpMethod = "POST")
	public ResponseEntity<Map<String, Object>> InterfaceAuthority(@RequestBody Authority authority) {
		Map<String, Object> map = new HashMap<String, Object>();
		String uuid = UUID.randomUUID().toString().replaceAll("-", "");
		authority.setUuid(uuid);
		authority.setAuthority_type("4");
		int i =authorityMapper.addInterfaceAuthority(authority);
		if (i > 0) {
			map.put("data", authority);
			map.put("msg", "接口权限添加成功！");
			map.put("error_code", 1);
		} else if (i<= 0) {
			map.put("msg", "接口权限添加失败！");
			map.put("error_code", 0);
		} else {
			map.put("msg", "服务器出问题了！");
			map.put("error_code", 2);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/deleteInterfaceAuthority", method = RequestMethod.DELETE)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/deleteInterfaceAuthority--DELETE')")
	@ApiOperation(value = "删除接口权限", notes = "删除接口权限记录", httpMethod = "DELETE")
	public ResponseEntity<Map<String, Object>> deleteInterfaceAuthority(@RequestBody String authuuid) {
		Map<String, Object> map = new HashMap<String, Object>();
		int i =authorityMapper.deleteInterfaceAuthority(authuuid);
		if (i > 0) {
			map.put("msg", "接口权限删除成功！");
			map.put("error_code", 1);
		} else if (i<= 0) {
			map.put("msg", "接口权限删除失败！");
			map.put("error_code", 0);
		} else {
			map.put("msg", "服务器出问题了！");
			map.put("error_code", 2);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/deleteInterfaceAuthorityByMore", method = RequestMethod.DELETE)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/deleteInterfaceAuthorityByMore--DELETE')")
	@ApiOperation(value = "批量删除接口权限", notes = "批量删除接口权限记录", httpMethod = "DELETE")
	public ResponseEntity<Map<String, Object>> deleteInterfaceAuthorityByMore(@RequestBody String[] authuuids) {
		Map<String, Object> map = new HashMap<String, Object>();
		for (String authuuid : authuuids) {
			int i =authorityMapper.deleteInterfaceAuthority(authuuid);
			if (i > 0) {
				map.put("msg", "接口权限删除成功！");
				map.put("error_code", 1);
			} else if (i<= 0) {
				map.put("msg", "接口权限删除失败！");
				map.put("error_code", 0);
			} else {
				map.put("msg", "服务器出问题了！");
				map.put("error_code", 2);
			}
		}
		
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
	

	@RequestMapping(value = "/getAllInterfaceAuthority", method = RequestMethod.GET)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/getAllInterfaceAuthority--GET')")
	@ApiOperation(value = "获取所有接口权限", notes = "获取所有接口权限记录", httpMethod = "GET")
	public ResponseEntity<Map<String, Object>> getAllInterfaceAuthority() {
		Map<String, Object> map = new HashMap<String, Object>();
		List<Authority> authoritys = authorityMapper.getAllAuthorityByAuthority_type("4");
		if (authoritys.size() > 0) {
			map.put("data", authoritys);
			map.put("msg", "所有接口权限获取成功！");
			map.put("error_code", 1);
			log.info("resource：" + map);
		} else if (authoritys.size()<= 0) {
			map.put("data", authoritys);
			map.put("msg", "所有接口权限获取失败或者为空！");
			map.put("error_code", 0);
			log.info("resource：" + map);
		} else {
			map.put("msg", "服务器出问题了！");
			map.put("error_code", 2);
			log.info("resource：" + map);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
	
	
	@RequestMapping(value = "/getAllAuthorityByAuthority_type", method = RequestMethod.GET)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/getAllViewsAuthority--GET')")
	@ApiOperation(value = "根据权限类型获取所有权限", notes = "根据权限类型获取所有权限记录", httpMethod = "GET")
	public ResponseEntity<Map<String, Object>> getAllViewsAuthority(@RequestParam(value = "authority_type") String authority_type) {
		Map<String, Object> map = new HashMap<String, Object>();
		List<Authority> authoritys = authorityMapper.getAllAuthorityByAuthority_type(authority_type);
		if (authoritys.size() > 0) {
			map.put("data", authoritys);
			map.put("msg", "权限类型为“"+authority_type+"”的所有权限获取成功！");
			map.put("error_code", 1);
		} else if (authoritys.size()<= 0) {
			map.put("data", authoritys);
			map.put("msg", "权限类型为“"+authority_type+"”的所有权限获取失败或者为空！");
			map.put("error_code", 0);
		} else {
			map.put("msg", "服务器出问题了！");
			map.put("error_code", 2);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/getAllAuthority", method = RequestMethod.GET)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/getAllAuthority--GET')")
	@ApiOperation(value = "获取所有权限", notes = "获取所有权限记录", httpMethod = "GET")
	public ResponseEntity<Map<String, Object>> getAllAuthority() {
		Map<String, Object> map = new HashMap<String, Object>();
		List<Authority> authoritys = authorityMapper.getAllAuthority();
		if (authoritys.size() > 0) {
			map.put("data", authoritys);
			map.put("msg", "所有权限获取成功！");
			map.put("error_code", 1);
		} else if (authoritys.size()<= 0) {
			map.put("data", authoritys);
			map.put("msg", "所有权限获取失败或者为空！");
			map.put("error_code", 0);
		} else {
			map.put("msg", "服务器出问题了！");
			map.put("error_code", 2);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/getAllAuthorityByLike", method = RequestMethod.GET)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/getAllAuthorityByLike--GET')")
	@ApiOperation(value = "获取查询权限", notes = "获取查询权限记录，若记录类型为空则获取所有类型权限", httpMethod = "GET")
	public ResponseEntity<Map<String, Object>> getAllAuthorityByLike(@RequestParam(value = "authority_name") String authority_name,
			@RequestParam(value = "authority_type", required = false) String authority_type) {
		Map<String, Object> map = new HashMap<String, Object>();
		authority_name="%"+authority_name.replace(" ", "")+"%";
		List<Authority> authoritys=new ArrayList<Authority>();
		if(authority_type==null){
			authoritys = authorityMapper.getAllAuthorityByLike(authority_name);
		}else{
			authoritys = authorityMapper.getAuthorityByLike(authority_name,authority_type);
		}
		if (authoritys.size() > 0) {
			map.put("data", authoritys);
			map.put("msg", "查询权限获取成功！");
			map.put("error_code", 1);
		} else if (authoritys.size()<= 0) {
			map.put("data", authoritys);
			map.put("msg", "查询权限获取失败或者为空！");
			map.put("error_code", 0);
		} else {
			map.put("msg", "服务器出问题了！");
			map.put("error_code", 2);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
	
	

}
