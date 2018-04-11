package com.hcycom.jhipster.web.rest;

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
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.codahale.metrics.annotation.Timed;
import com.hcycom.jhipster.domain.Attribute_values;
import com.hcycom.jhipster.domain.Role;
import com.hcycom.jhipster.service.mapper.Attribute_valuesMapper;
import com.hcycom.jhipster.service.mapper.ResourceMapper;
import com.hcycom.jhipster.service.mapper.RoleMapper;

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
@Api(tags = { "角色管理" }, description = "角色管理接口")
public class RolesController {
	private final Logger log = LoggerFactory.getLogger(RolesController.class);

	@Autowired
	private RoleMapper roleMapperr;

	@Autowired
	private Attribute_valuesMapper attribute_valuesMapper;
	
	@Autowired
	private ResourceMapper resourceMapper;

	@RequestMapping(value = "/role", method = RequestMethod.POST)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/role--POST')")
	@ApiOperation(value = "创建角色", notes = "传入角色表参数，创建角色", httpMethod = "POST")
	public ResponseEntity<Map<String, Object>> role(@RequestBody Role role) {
		Map<String, Object> map = new HashMap<String, Object>();
		Role role2 = roleMapperr.getRoleByRole_name(role.getRole_name());
		int i = 0;
		if (role2 == null) {
			String uuid = UUID.randomUUID().toString().replaceAll("-", "");
			role.setUuid(uuid);
			i = roleMapperr.addRole(role);
			if (i == 0) {
				map.put("msg", "角色【" + role.getRole_name() + "】创建失败！");
				map.put("error_code", 0);
			} else if (i > 0) {
				map.put("data", role);
				map.put("msg", "角色【" + role.getRole_name() + "】创建成功！");
				map.put("error_code", 1);
			} else {
				map.put("msg", "服务器出问题了！");
				map.put("error_code", 2);
			}
		} else {
			map.put("msg", "角色已经存在！");
			map.put("error_code", 0);
		}

		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	@RequestMapping(value = "/role_update", method = RequestMethod.PUT)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/role_update--PUT')")
	@ApiOperation(value = "修改角色", notes = "传入角色表参数，根据角色id修改角色", httpMethod = "PUT")
	public ResponseEntity<Map<String, Object>> role_update(@RequestBody Role role) {
		Map<String, Object> map = new HashMap<String, Object>();

		Role role2 = roleMapperr.getRoleByRole_name(role.getRole_name());
		int i = 0;
		if (role.getUuid().equals("1") || role.getUuid().equals("2")) {
			map.put("msg", "默认角色不可修改！");
			map.put("error_code", 1);
		} else if (role2 != null && !role2.getUuid().equals(role.getUuid())) {
			map.put("msg", "角色已经存在修改失败！");
			map.put("error_code", 1);
		} else {
			i = roleMapperr.updateRole(role);
			if (i == 0) {
				map.put("msg", "角色【" + role.getRole_name() + "】修改失败！");
				map.put("error_code", 0);
			} else if (i > 0) {
				map.put("data", role);
				map.put("msg", "角色【" + role.getRole_name() + "】修改成功！");
				map.put("error_code", 1);
			} else {
				map.put("msg", "服务器出问题了！");
				map.put("error_code", 2);
			}
		}

		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	@RequestMapping(value = "/role_delete/{uuid}", method = RequestMethod.DELETE)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/role_delete/{uuid}--DELETE')")
	@ApiOperation(value = "删除角色", notes = "传入角色表参数，根据角色id删除角色", httpMethod = "DELETE")
	public ResponseEntity<Map<String, Object>> role_delete(@PathVariable String uuid) {
		Map<String, Object> map = new HashMap<String, Object>();
		Role role = new Role();
		role.setUuid(uuid);
		if (role.getUuid().equals("1") || role.getUuid().equals("2")) {
			map.put("msg", "默认角色不可删除！");
			map.put("error_code", 1);
		} else {
			int i = roleMapperr.deleteRole(role);
			if (i == 0) {
				map.put("msg", "角色【" + role.getRole_name() + "】删除失败！");
				map.put("error_code", 0);
			} else if (i > 0) {
				Attribute_values attribute_values = new Attribute_values();
				attribute_values.setResource_name("user");
				attribute_values.setAttribute_key("roles");
				attribute_values.setValue(uuid + ",");
				attribute_values.setSave_table(
						resourceMapper.findResoureByResource_name(attribute_values.getResource_name()).getSave_table());
				attribute_valuesMapper.replaceUpdateAttribute_values(attribute_values);
				map.put("data", role);
				map.put("msg", "角色【" + role.getRole_name() + "】删除成功！");
				map.put("error_code", 1);
			} else {
				map.put("msg", "服务器出问题了！");
				map.put("error_code", 2);
			}
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	@RequestMapping(value = "/role_deleteByMore", method = RequestMethod.DELETE)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/role_deleteByMore--DELETE')")
	@ApiOperation(value = "批量删除角色", notes = "根据角色id数组，批量删除角色", httpMethod = "DELETE")
	public ResponseEntity<Map<String, Object>> role_deleteByMore(@RequestBody String[] uuids) {
		Map<String, Object> map = new HashMap<String, Object>();
		for (String uuid : uuids) {
			Role role = new Role();
			role.setUuid(uuid);
			if (role.getUuid().equals("1") || role.getUuid().equals("2")) {
				map.put("msg", "默认角色不可删除！");
				map.put("error_code", 0);
				return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
			} else {
				roleMapperr.deleteRole(role);
				Attribute_values attribute_values = new Attribute_values();
				attribute_values.setResource_name("user");
				attribute_values.setAttribute_key("roles");
				attribute_values.setValue(uuid + ",");
				attribute_values.setSave_table(
						resourceMapper.findResoureByResource_name(attribute_values.getResource_name()).getSave_table());
				attribute_valuesMapper.replaceUpdateAttribute_values(attribute_values);
			}

		}
		map.put("msg", "角色批量删除成功！");
		map.put("error_code", 1);

		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	@RequestMapping(value = "/role_get/{uuid}", method = RequestMethod.GET)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/role_get/{uuid}--GET')")
	@ApiOperation(value = "获取角色", notes = "传入资源表参数，根据角色id获取角色", httpMethod = "GET")
	public ResponseEntity<Map<String, Object>> resource_get(@PathVariable String uuid) {
		log.info("request roleuuid：" + uuid);
		Role role = new Role();
		Map<String, Object> map = new HashMap<String, Object>();
		role = roleMapperr.getUsersAuthority(uuid);
		if (role != null) {
			map.put("data", role);
			map.put("msg", "角色【" + role.getRole_name() + "】获取成功！");
			map.put("error_code", 1);
		} else {
			map.put("data", role);
			map.put("msg", "角色获取失败或为空！");
			map.put("error_code", 0);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	@RequestMapping(value = "/role_getAll", method = RequestMethod.GET)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/role_getAll--GET')")
	@ApiOperation(value = "获取所有角色", notes = "获取所有角色", httpMethod = "GET")
	public ResponseEntity<Map<String, Object>> resource_getAll() {
		Map<String, Object> map = new HashMap<String, Object>();
		List<Role> roles = roleMapperr.getAllAuthority();
		if (roles.size() > 0) {
			map.put("data", roles);
			map.put("msg", "所有角色获取成功！");
			map.put("error_code", 1);
		} else if (roles.size() <= 0) {
			map.put("data", roles);
			map.put("msg", "所有角色获取失败或为空！");
			map.put("error_code", 0);
		} else {
			map.put("msg", "服务器出问题了！");
			map.put("error_code", 2);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	@RequestMapping(value = "/getRoleByLike", method = RequestMethod.GET)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/getRoleByLike--GET')")
	@ApiOperation(value = "获取筛选角色", notes = "获取筛选角色", httpMethod = "GET")
	public ResponseEntity<Map<String, Object>> getRoleByLike(@RequestParam("role_name")String role_name) {
		Map<String, Object> map = new HashMap<String, Object>();
		role_name="%"+role_name.replace(" ", "")+"%";
		List<Role> roles = roleMapperr.getAuthoritybyLike(role_name);
		if (roles.size() > 0) {
			map.put("data", roles);
			map.put("msg", "筛选角色获取成功！");
			map.put("error_code", 1);
		} else if (roles.size() <= 0) {
			map.put("data", roles);
			map.put("msg", "筛选角色获取失败或为空！");
			map.put("error_code", 0);
		} else {
			map.put("msg", "服务器出问题了！");
			map.put("error_code", 2);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

}
