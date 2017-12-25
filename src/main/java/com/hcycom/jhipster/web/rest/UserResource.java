package com.hcycom.jhipster.web.rest;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.codahale.metrics.annotation.Timed;
import com.hcycom.jhipster.config.Constants;
import com.hcycom.jhipster.domain.Attribute;
import com.hcycom.jhipster.domain.Attribute_values;
import com.hcycom.jhipster.domain.Group;
import com.hcycom.jhipster.domain.Role;
import com.hcycom.jhipster.service.mapper.AttributeMapper;
import com.hcycom.jhipster.service.mapper.Attribute_valuesMapper;
import com.hcycom.jhipster.service.mapper.GroupMapper;
import com.hcycom.jhipster.service.mapper.RoleMapper;
import com.hcycom.jhipster.web.rest.errors.BadRequestAlertException;
import com.hcycom.jhipster.web.rest.errors.EmailAlreadyUsedException;
import com.hcycom.jhipster.web.rest.errors.InternalServerErrorException;
import com.hcycom.jhipster.web.rest.errors.LoginAlreadyUsedException;
import com.hcycom.jhipster.web.rest.util.HeaderUtil;
import com.hcycom.jhipster.web.rest.util.PaginationUtil;

import io.github.jhipster.web.util.ResponseUtil;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;

@RestController
@RequestMapping("/api")
@Api(tags = { "用户管理" })
public class UserResource {

	private final Logger log = LoggerFactory.getLogger(UserResource.class);

	// private final UserService userService;
	//
	// public UserResource(UserService userService) {
	//
	// this.userService = userService;
	// }

	private final Attribute_valuesMapper attribute_valuesMapper;

	private final RoleMapper roleMapper;

	@Autowired
	private AttributeMapper attributeMapper;
	
	@Autowired
	private GroupMapper groupMapper;

	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	public UserResource(Attribute_valuesMapper attribute_valuesMapper, RoleMapper roleMapper) {

		this.attribute_valuesMapper = attribute_valuesMapper;
		this.roleMapper = roleMapper;
	}

	/**
	 * POST /users : Creates a new user.
	 * <p>
	 * Creates a new user if the login and email are not already used, and sends
	 * an mail with an activation link. The user needs to be activated on
	 * creation.
	 *
	 * @param managedUserVM
	 *            the user to create
	 * @return the ResponseEntity with status 201 (Created) and with body the
	 *         new user, or with status 400 (Bad Request) if the login or email
	 *         is already in use
	 * @throws URISyntaxException
	 *             if the Location URI syntax is incorrect
	 * @throws BadRequestAlertException
	 *             400 (Bad Request) if the login or email is already in use
	 */
	@PostMapping("/users")
	@Timed
	@ApiOperation(value = "新增用户", notes = "新增用户已经激活", httpMethod = "POST")
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/users_post')")
	@ApiParam(required = true, name = "username,sex,phone,password,name_cn,head_image,email,authorities", value = "需要传入的这些值,其他值为空，authorities为角色名称数组")
	public ResponseEntity<Map<String, Object>> createUser(@Valid @RequestBody Map<String, Object> map)
			throws URISyntaxException {
		log.debug("REST request to save User : {}", map);
		String username = "";
		if (map.get("username") != null) {
			username = (String) map.get("username");
		}
		if (attribute_valuesMapper.findIdByName("user", username) != null || username.equals("internal")) {
			throw new LoginAlreadyUsedException();
		}
		String password = (String) map.get("password");
		if (password == null || password.equals("")) {
			password = "hcy123";
		}
		@SuppressWarnings("unchecked")
		List<String> groups = (List<String>) map.get("groups");
		String group = "";
		for (String string : groups) {
			group += string + ",";
		}
		map.put("groups", group);
		@SuppressWarnings("unchecked")
		List<String> authorities = (List<String>) map.get("authorities");
		List<String> au = new ArrayList<String>();
		if (authorities != null) {
			for (String string : authorities) {
				Role role = new Role();
				role = roleMapper.getRoleByRole_name(string);
				au.add(role.getUuid());
			}
			String roles = "";
			for (String string : au) {
				roles += string + ",";
			}
			map.put("roles", roles);
		}else{
			map.put("roles", "");
		}
		String uuid = UUID.randomUUID().toString().replaceAll("-", "");
		String encryptedPassword = passwordEncoder.encode(password);
		map.put("password", encryptedPassword);
		map.put("id", uuid);
		map.put("status", 1);
		map.remove("authorities");
		map.remove("login");
		for (String key : map.keySet()) {
			Attribute_values attribute_values = new Attribute_values();
			attribute_values.setUuid(uuid);
			attribute_values.setResource_name("user");
			attribute_values.setAttribute_key(key);
			attribute_values.setValue(map.get(key) + "");
			attribute_valuesMapper.addAttribute_values(attribute_values);
		}

		return ResponseEntity.created(new URI("/api/users/" + map.get("username")))
				.headers(HeaderUtil.createAlert("userManagement.created", (String) map.get("username"))).body(map);

	}

	/**
	 * PUT /users : Updates an existing User.
	 *
	 * @param managedUserVM
	 *            the user to update
	 * @return the ResponseEntity with status 200 (OK) and with body the updated
	 *         user
	 * @throws EmailAlreadyUsedException
	 *             400 (Bad Request) if the email is already in use
	 * @throws LoginAlreadyUsedException
	 *             400 (Bad Request) if the login is already in use
	 */
	@PutMapping("/users")
	@Timed
	@ApiOperation(value = "修改用户", notes = "修改用户所有信息", httpMethod = "PUT")
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/users_PUT')")
	@ApiParam(required = true, name = "sex,phone,password,name_cn,head_image,email,authorities", value = "需要传入的这些值,其他值为空，authorities为角色名称数组")
	public ResponseEntity<Map<String, Object>> updateUser(@Valid @RequestBody Map<String, Object> map) {
		log.debug("REST request to update User : {}", map);
		String username = (String) map.get("username");
		String id = (String) map.get("id");
		map.remove("password");
		map.remove("username");
		map.remove("id");
		@SuppressWarnings("unchecked")
		List<String> groups = (List<String>) map.get("groups");
		String group = "";
		for (String string : groups) {
			group += string + ",";
		}
		map.put("groups", group);
		@SuppressWarnings("unchecked")
		List<String> authorities = (List<String>) map.get("authorities");
		List<String> au = new ArrayList<String>();
		if (authorities != null) {
			for (String string : authorities) {
				Role role = new Role();
				role = roleMapper.getRoleByRole_name(string);
				au.add(role.getUuid());
			}
			String roles = "";
			for (String string : au) {
				roles += string + ",";
			}
			map.put("roles", roles);
		}else{
			map.put("roles", "");
		}
		map.remove("authorities");
		map.remove("login");
		Attribute_values value = new Attribute_values();
		value.setUuid(id);
		List<Attribute_values> list = attribute_valuesMapper.findAttribute_valuesByResource_nameANDUuid(value);
		if (list == null) {
			throw new InternalServerErrorException("User could not be found");
		}
		for (String key : map.keySet()) {
			Attribute_values attribute_values2 = new Attribute_values();
			attribute_values2.setUuid(id);
			attribute_values2.setResource_name("user");
			attribute_values2.setAttribute_key(key);
			attribute_values2.setValue(map.get(key) + "");
			attribute_valuesMapper.updateAttribute_values(attribute_values2);
		}
		Optional<Map<String, Object>> optional = Optional.of(map);
		return ResponseUtil.wrapOrNotFound(optional, HeaderUtil.createAlert("userManagement.updated", username));
	}

	/**
	 * GET /users : get all users.
	 *
	 * @param pageable
	 *            the pagination information
	 * @return the ResponseEntity with status 200 (OK) and with body all users
	 */
	@GetMapping("/users")
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/users_GET')")
	@ApiOperation(value = "分页获取用户", httpMethod = "GET", notes = "通过分页值获取用户")
	public ResponseEntity<List<Map<String, Object>>> getAllUsers(@ApiParam Pageable pageable) {
		Attribute_values attribute_values = new Attribute_values();
		attribute_values.setResource_name("user");
		List<String> uuids = attribute_valuesMapper.findAttribute_valuesByPage(pageable, "user");

		String ListID = "";
		for (String string : uuids) {
			ListID += "\"" + string + "\",";
		}
		if(!ListID.equals("")){
		ListID = ListID.substring(0, ListID.length() - 1);
		}
		List<Attribute_values> list = attribute_valuesMapper.findAttribute_valuesByListID(ListID, "user");
		List<Map<String, Object>> usermap = new ArrayList<Map<String, Object>>();
		for (Attribute_values values : list) {
			if (values.getAttribute_key().equals("id")) {
				Map<String, Object> map = new HashMap<String, Object>();
				for (Attribute_values values2 : list) {
					if (values2.getUuid().equals(values.getValue())) {
						map.put(values2.getAttribute_key(), values2.getValue());
					}
					
				}
				Set<String> groupnames = new HashSet<>();
				String[] groupids = ((String) map.get("groups")).split(",");
				for (String groupid : groupids) {
					Group group = groupMapper.getGroupById(groupid);
					if (group != null) {
						groupnames.add(group.getGroup_name());
					}
				}
				Set<String> authorities = new HashSet<>();
				String[] rolesids = ((String) map.get("roles")).split(",");
				for (String rolesid : rolesids) {
					Role role=roleMapper.getUsersAuthority(rolesid);
					if(role!=null){
						authorities.add(role.getRole_name());
					}
				}
				map.remove("password");
				map.put("login", map.get("username"));
				map.put("authorities", authorities);
				map.put("groupnames", groupnames);
				usermap.add(map);
			}
		}

		final Page<Map<String, Object>> page = new PageImpl<Map<String, Object>>(usermap);
		HttpHeaders headers = PaginationUtil.generatePaginationHttpHeaders(page, "/api/users");
		return new ResponseEntity<>(page.getContent(), headers, HttpStatus.OK);
	}

	/**
	 * @return a string list of the all of the roles
	 */
	@GetMapping("/users/authorities")
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/users/authorities')")
	@ApiOperation(value = "获取角色名称", httpMethod = "GET", notes = "获取所有的角色名称")
	public List<String> getAuthorities() {

		return roleMapper.getAllAuthority().stream().map(Role::getRole_name).collect(Collectors.toList());
	}

	/**
	 * GET /users/:login : get the "login" user.
	 *
	 * @param login
	 *            the login of the user to find
	 * @return the ResponseEntity with status 200 (OK) and with body the "login"
	 *         user, or with status 404 (Not Found)
	 */
	@GetMapping("/users/{login:" + Constants.LOGIN_REGEX + "}")
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/users/{login}_GET')")
	@ApiOperation(value = "获取用户", httpMethod = "GET", notes = "获取用户所有信息，login为用户名称")
	@ApiParam(name = "login", value = "参数类型为String,是用户的名称", required = true)
	public ResponseEntity<Map<String, Object>> getUser(@PathVariable String login) {
		log.debug("REST request to get User : {}", login);
		List<Attribute_values> list = attribute_valuesMapper.findUserByName("user", login);
		if (list == null) {
			throw new InternalServerErrorException("User could not be found");
		}
		Map<String,Object> map = new HashMap<String,Object>();
		for (Attribute_values attribute_values : list) {
			map.put(attribute_values.getAttribute_key(), attribute_values.getValue());
		}
		Set<String> groupnames = new HashSet<>();
		String[] groupids = ((String) map.get("groups")).split(",");
		for (String groupid : groupids) {
			Group group = groupMapper.getGroupById(groupid);
			if (group != null) {
				groupnames.add(group.getGroup_name());
			}
		}
		Set<String> authorities = new HashSet<>();
		if ((String) map.get("roles") != null || !map.get("roles").equals("")) {
			String[] rolesids = ((String) map.get("roles")).split(",");
			for (String rolesid : rolesids) {
				Role role=roleMapper.getUsersAuthority(rolesid);
				if(role!=null){
					authorities.add(role.getRole_name());
				}
			}
		}
		map.put("login", map.get("username"));
		map.put("authorities", authorities);
		map.put("groupnames", groupnames);
		map.remove("password");
		return ResponseUtil.wrapOrNotFound(Optional.of(map));
	}

	/**
	 * DELETE /users/:login : delete the "login" User.
	 *
	 * @param login
	 *            the login of the user to delete
	 * @return the ResponseEntity with status 200 (OK)
	 */
	@DeleteMapping("/users/{login:" + Constants.LOGIN_REGEX + "}")
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/users/{login}_DELETE')")
	@ApiOperation(value = "删除用户，根据用户名", httpMethod = "DELETE", notes = "删除用户所有信息，login为用户名称")
	@ApiParam(name = "login", value = "参数类型为String,是用户的名称", required = true)
	public ResponseEntity<Void> deleteUser(@PathVariable String login) {
		log.debug("REST request to delete User: {}", login);
		Attribute_values values = attribute_valuesMapper.findIdByName("user", login);
		Attribute_values attribute_values = new Attribute_values();
		attribute_values.setResource_name("user");
		attribute_values.setUuid(values.getUuid());
		attribute_valuesMapper.deleteAttribute_valuesByResource_nameAndUuid(attribute_values);
		return ResponseEntity.ok().headers(HeaderUtil.createAlert("userManagement.deleted", login)).build();
	}


	@DeleteMapping("/usersByMore")
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/usersByMore')")
	@ApiOperation(value = "删除多个用户", httpMethod = "DELETE", notes = "删除多个用户根据id数组")
	@ApiParam(name = "ids", value = "参数类型为String[],为用户id的数组", required = true)
	public void deleteUserByMore(@RequestBody String[] ids) {
		for (String id : ids) {
			Attribute_values attribute_values = new Attribute_values();
			attribute_values.setResource_name("user");
			attribute_values.setUuid(id);
			attribute_valuesMapper.deleteAttribute_valuesByResource_nameAndUuid(attribute_values);
		}

	}

	/**
	 * 获取所有用户
	 * 
	 * @return
	 */
	@GetMapping("/allusers")
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/allusers')")
	@ApiOperation(value = "获取所有用户", notes = "获取所有用户所有信息", httpMethod = "GET")
	public ResponseEntity<Map<String, Object>> getAllUser() {
		Attribute_values attribute_values = new Attribute_values();
		attribute_values.setResource_name("user");
		List<Attribute_values> list = attribute_valuesMapper.findAttribute_valuesByResource_name(attribute_values);
		List<Map<String, Object>> usermap = new ArrayList<Map<String, Object>>();
		for (Attribute_values values : list) {
			if (values.getAttribute_key().equals("id")) {
				Map<String, Object> map = new HashMap<String, Object>();
				for (Attribute_values values2 : list) {
					if (values2.getUuid().equals(values.getValue())) {
						map.put(values2.getAttribute_key(), values2.getValue());
					}
				}
				Set<String> groupnames = new HashSet<>();
				String[] groupids = ((String) map.get("groups")).split(",");
				for (String groupid : groupids) {
					Group group = groupMapper.getGroupById(groupid);
					if (group != null) {
						groupnames.add(group.getGroup_name());
					}
				}
				Set<String> authorities = new HashSet<>();
				if ((String) map.get("roles") != null || !map.get("roles").equals("")) {
					String[] rolesids = ((String) map.get("roles")).split(",");
					for (String rolesid : rolesids) {
						Role role=roleMapper.getUsersAuthority(rolesid);
						if(role!=null){
							authorities.add(role.getRole_name());
						}
					}
				}
				map.remove("password");
				map.put("login", map.get("username"));
				map.put("authorities", authorities);
				map.put("groupnames", groupnames);
				usermap.add(map);
			}
		}
		Map<String, Object> map = new HashMap<String, Object>();
		if (list.size() > 0) {
			map.put("allUser", usermap);
			map.put("msg", "成功获取所有用户！");
			map.put("error_code", 1);
		} else if (list.size() == 0) {
			map.put("msg", "获取所有用户失败或所有用户为空！");
			map.put("error_code", 0);
		} else {
			map.put("msg", "服务器出问题了！");
			map.put("error_code", 2);
		}

		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	/**
	 * 获取所有用户表属性
	 * 
	 * @return
	 */
	@GetMapping("/allusersTable")
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/allusersTable')")
	@ApiOperation(value = "获取所有用户表属性", notes = "获取所有用户表属性", httpMethod = "GET")
	public ResponseEntity<Map<String, Object>> getAllUserTable() {
		Attribute attribute = new Attribute();
		attribute.setResource_name_foreign("user");
		List<Attribute> list = attributeMapper.findAttributeByResource_name(attribute);

		Map<String, Object> map = new HashMap<String, Object>();
		if (list.size() > 0) {
			map.put("allUser", list);
			map.put("msg", "成功获取所有用户表属性！");
			map.put("error_code", 1);
		} else if (list.size() == 0) {
			map.put("msg", "获取所有用户表属性失败或用户表属性为空！");
			map.put("error_code", 0);
		} else {
			map.put("msg", "服务器出问题了！");
			map.put("error_code", 2);
		}
		
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
	
	/**
	 * 获取所有用户表属性
	 * 
	 * @return
	 */
	@PostMapping("/getusersByLike")
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/getusersByLike')")
	@ApiOperation(value = "获取筛选用户", notes = "获取筛选后用户", httpMethod = "POST")
	public ResponseEntity<Map<String, Object>> getusersByLike(@RequestBody Map<String, Object> map) {
		List<String> uuids=new ArrayList<String>();
		for (String key : map.keySet()) {
			Attribute_values attribute_values = new Attribute_values();
			attribute_values.setResource_name("user");
			attribute_values.setAttribute_key(key);
			String sql="\"%"+map.get(key) + "%\"";
			List<String> list2 =attribute_valuesMapper.findAttribute_valuesByKeyAndValue(attribute_values,sql);
			list2.removeAll(uuids);
			uuids.addAll(list2);
		}
		String ListID = "";
		for (String string : uuids) {
			ListID += "\"" + string + "\",";
		}
		ListID = ListID.substring(0, ListID.length() - 1);
		List<Attribute_values> list = attribute_valuesMapper.findAttribute_valuesByListID(ListID, "user");
		List<Map<String, Object>> usermap = new ArrayList<Map<String, Object>>();
		for (Attribute_values values : list) {
			if (values.getAttribute_key().equals("id")) {
				Map<String, Object> map2 = new HashMap<String, Object>();
				for (Attribute_values values2 : list) {
					if (values2.getUuid().equals(values.getValue())) {
						map2.put(values2.getAttribute_key(), values2.getValue());
					}
				}
				Set<String> groupnames = new HashSet<>();
				String[] groupids = ((String) map.get("groups")).split(",");
				for (String groupid : groupids) {
					Group group = groupMapper.getGroupById(groupid);
					if (group != null) {
						groupnames.add(group.getGroup_name());
					}
				}
				Set<String> authorities = new HashSet<>();
				String[] rolesids = ((String) map2.get("roles")).split(",");
				for (String rolesid : rolesids) {
					Role role=roleMapper.getUsersAuthority(rolesid);
					if(role!=null){
						authorities.add(role.getRole_name());
					}
				}
				map2.remove("password");
				map2.put("login", map.get("username"));
				map2.put("groupnames", groupnames);
				map2.put("authorities", authorities);
				usermap.add(map2);
			}
		}
		Map<String, Object> map3 = new HashMap<String, Object>();
		if (list.size() > 0) {
			map3.put("allUser", usermap);
			map3.put("LikeMap", map);
			map3.put("msg", "成功获取筛选后用户！");
			map3.put("error_code", 1);
		} else if (list.size() == 0) {
			map3.put("LikeMap", map);
			map3.put("msg", "获取筛选后用户失败或获取筛选后用户为空！");
			map3.put("error_code", 0);
		} else {
			map3.put("msg", "服务器出问题了！");
			map3.put("error_code", 2);
		}
		
		return new ResponseEntity<Map<String, Object>>(map3, HttpStatus.OK);
	}
}
