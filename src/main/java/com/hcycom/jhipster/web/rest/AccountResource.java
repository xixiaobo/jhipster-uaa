package com.hcycom.jhipster.web.rest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.codahale.metrics.annotation.Timed;
import com.hcycom.jhipster.domain.Attribute_values;
import com.hcycom.jhipster.domain.Group;
import com.hcycom.jhipster.domain.Role;
import com.hcycom.jhipster.security.SecurityUtils;
import com.hcycom.jhipster.service.mapper.Attribute_valuesMapper;
import com.hcycom.jhipster.service.mapper.GroupMapper;
import com.hcycom.jhipster.service.mapper.ResourceMapper;
import com.hcycom.jhipster.service.mapper.RoleMapper;
import com.hcycom.jhipster.web.rest.errors.EmailAlreadyUsedException;
import com.hcycom.jhipster.web.rest.errors.InternalServerErrorException;
import com.hcycom.jhipster.web.rest.errors.InvalidPasswordException;
import com.hcycom.jhipster.web.rest.errors.LoginAlreadyUsedException;
import com.hcycom.jhipster.web.rest.vm.UsernameAndPasswordVM;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;

/**
 * REST controller for managing the current user's account.
 */
@RestController
@RequestMapping("/api")
@Api(tags = { "账户资源管理" })
public class AccountResource {

	private final Logger log = LoggerFactory.getLogger(AccountResource.class);

	// private final UserService userService;

	private final Attribute_valuesMapper attribute_valuesMapper;

	private final RoleMapper roleMapper;


	private final ResourceMapper resourceMapper;

	@Autowired
	private GroupMapper groupMapper;

	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	public AccountResource(ResourceMapper resourceMapper,Attribute_valuesMapper attribute_valuesMapper, RoleMapper roleMapper) {
		this.resourceMapper = resourceMapper;
		this.attribute_valuesMapper = attribute_valuesMapper;
		this.roleMapper = roleMapper;
	}

	/**
	 * POST /register : register the user.
	 *
	 * @param managedUserVM
	 *            the managed user View Model
	 * @throws InvalidPasswordException
	 *             400 (Bad Request) if the password is incorrect
	 * @throws EmailAlreadyUsedException
	 *             400 (Bad Request) if the email is already used
	 * @throws LoginAlreadyUsedException
	 *             400 (Bad Request) if the login is already used
	 */
	@PostMapping("/register")
	@Timed
	@ResponseStatus(HttpStatus.CREATED)
	@ApiOperation(value = "注册用户", notes = "新增用户未激活，无权限控制", httpMethod = "POST")
	public void registerAccount(@RequestBody Map<String, Object> map) {
		String username = (String) map.get("username");
		if (username == null || username.equals("")) {
			username = "";
		}
		Attribute_values values = new Attribute_values();
		values = attribute_valuesMapper.findIdByName("user", username);
		if (values != null || username.equals("internal")) {
			throw new LoginAlreadyUsedException();
		}
		String password = (String) map.get("password");
		if (password == null || password.equals("")) {
			password = "hcy123";
		}
		if (map.containsKey("groups")) {
			@SuppressWarnings("unchecked")
			List<String> groups = (List<String>) map.get("groups");
			String group = "";
			for (String string : groups) {
				group += string + ",";
			}
			map.put("groups", group);
		} else {
			map.put("groups", "");
		}
		if (map.containsKey("authorities")) {
			@SuppressWarnings("unchecked")
			List<String> authorities = (List<String>) map.get("authorities");
			List<String> au = new ArrayList<String>();
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
		} else {
			map.put("roles", "");
		}
		if (!checkPasswordLength(password)) {
			throw new InvalidPasswordException();
		}
		String uuid = UUID.randomUUID().toString().replaceAll("-", "");
		String encryptedPassword = passwordEncoder.encode(password);
		map.put("password", encryptedPassword);
		map.put("id", uuid);
		map.put("status", 0);
		map.remove("authorities");
		map.remove("login");
		for (String key : map.keySet()) {
			Attribute_values attribute_values = new Attribute_values();
			attribute_values.setUuid(uuid);
			attribute_values.setResource_name("user");
			attribute_values.setAttribute_key(key);
			attribute_values.setValue(map.get(key) + "");
			attribute_values.setSave_table(resourceMapper.findResoureByResource_name(attribute_values.getResource_name()).getSave_table());
			attribute_valuesMapper.addAttribute_values(attribute_values);
		}
	}

	/**
	 * GET /activate : 激活已注册用户
	 *
	 * @param key
	 *            the activation key
	 * @throws RuntimeException
	 *             500 (Internal Server Error) if the user couldn't be activated
	 */
	@GetMapping("/activate")
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/activate--GET')")
	@ApiOperation(value = "激活用户", notes = "改变为未激活或用户激活", httpMethod = "GET")
	public void activateAccount(@RequestParam(value = "username") String username,
			@RequestParam(value = "status", required = false) String status) {
		Attribute_values attribute_values = attribute_valuesMapper.findIdByName("user", username);
		attribute_values.setAttribute_key("status");
		if (status == null) {
			attribute_values.setValue("1");
		} else if (status.equals("1")) {
			attribute_values.setValue("1");
		} else if (status.equals("0")) {
			attribute_values.setValue("0");
		} else {
			attribute_values.setValue("1");
		}
		attribute_values.setSave_table(resourceMapper.findResoureByResource_name(attribute_values.getResource_name()).getSave_table());
		attribute_valuesMapper.updateAttribute_values(attribute_values);

	}

	/**
	 * GET /authenticate : check if the user is authenticated, and return its
	 * login.
	 *
	 * @param request
	 *            the HTTP request
	 * @return the login if the user is authenticated
	 */
	@GetMapping("/authenticate")
	@Timed
	@ApiOperation(value = "检测是否有ouath2秘钥", httpMethod = "GET", notes = "检查用户是否经过身份验证，并返回其登录，无权限控制")
	public String isAuthenticated(HttpServletRequest request) {
		log.debug("REST request to check if the current user is authenticated");
		return request.getRemoteUser();
	}

	/**
	 * GET /account : get the current user.
	 *
	 * @return the current user
	 * @throws RuntimeException
	 *             500 (Internal Server Error) if the user couldn't be returned
	 */
	@GetMapping("/account")
	@Timed
	@ApiOperation(value = "获取当前登录用户信息", httpMethod = "GET", notes = "获取当前登录用户信息，无权限控制")
	public Map<String, Object> getAccount() {
		List<Attribute_values> list = attribute_valuesMapper.findUserByName("user",
				SecurityUtils.getCurrentUserLogin());
		if (list == null) {
			throw new InternalServerErrorException("User could not be found");
		}
		Map<String, Object> map = new HashMap<String, Object>();
		for (Attribute_values attribute_values : list) {
			map.put(attribute_values.getAttribute_key(), attribute_values.getValue());
		}
		Set<String> groupnames = new HashSet<>();
		if (map.containsKey("groups")) {
			String[] groupids = ((String) map.get("groups")).split(",");
			for (String groupid : groupids) {
				Group group = groupMapper.getGroupById(groupid);
				if (group != null) {
					groupnames.add(group.getGroup_name());
				}
			}
		}
		Set<String> authorities = new HashSet<>();
		if (map.containsKey("roles")) {
			String[] rolesids = ((String) map.get("roles")).split(",");
			for (String rolesid : rolesids) {
				Role role = roleMapper.getUsersAuthority(rolesid);
				if (role != null) {
					authorities.add(role.getRole_name());
				}
			}
		}
		map.put("login", map.get("username"));
		map.put("authorities", authorities);
		map.put("groupnames", groupnames);
		map.remove("password");
		return map;
	}

	/**
	 * POST /account : update the current user information.
	 *
	 * @param userDTO
	 *            the current user information
	 * @throws EmailAlreadyUsedException
	 *             400 (Bad Request) if the email is already used
	 * @throws RuntimeException
	 *             500 (Internal Server Error) if the user login wasn't found
	 */
	@PostMapping("/account")
	@Timed
	@ApiOperation(value = "更新当前登录用户信息", httpMethod = "POST", notes = "仅更新当前登录用户基础信息,仅修改三个值。name_cn,phone,email，无权限控制")
	@ApiParam(required = true, name = "name_cn,phone,email", value = "仅修改三个值，其他值为空")
	public void saveAccount(@Valid @RequestBody Map<String, String> map) {
		final String userLogin = SecurityUtils.getCurrentUserLogin();
		Attribute_values attribute_values = attribute_valuesMapper.findIdByName("user", userLogin);
		if (attribute_values == null) {
			throw new InternalServerErrorException("User could not be found");
		}
		attribute_values.setSave_table(resourceMapper.findResoureByResource_name(attribute_values.getResource_name()).getSave_table());
		if (map.containsKey("name_cn")) {
			attribute_values.setAttribute_key("name_cn");
			attribute_values.setValue(map.get("name_cn"));
			attribute_valuesMapper.updateAttribute_values(attribute_values);
		}
		if (map.containsKey("phone")) {
			attribute_values.setAttribute_key("phone");
			attribute_values.setValue(map.get("phone"));
			attribute_valuesMapper.updateAttribute_values(attribute_values);
		}
		if (map.containsKey("email")) {
			attribute_values.setAttribute_key("email");
			attribute_values.setValue(map.get("email"));
			attribute_valuesMapper.updateAttribute_values(attribute_values);
		}

	}

	/**
	 * POST /account/change-password : changes the current user's password
	 *
	 * @param password
	 *            the new password
	 * @throws InvalidPasswordException
	 *             400 (Bad Request) if the new password is incorrect
	 */
	@GetMapping(path = "/account/change-password")
	@Timed
	@ApiOperation(value = "更改当前登录用户的密码", httpMethod = "GET", notes = "更改当前登录用户的密码，无权限控制")
	@ApiParam(required = true, name = "password", value = "传入新密码直接修改")
	public void changePassword(@RequestParam("password") String password) {
		log.info("接受到的password："+password);
		if (!checkPasswordLength(password)) {
			throw new InvalidPasswordException();
		}
		final String userLogin = SecurityUtils.getCurrentUserLogin();
		Attribute_values attribute_values = attribute_valuesMapper.findIdByName("user", userLogin);
		if (attribute_values == null) {
			throw new InternalServerErrorException("User could not be found");
		}
		attribute_values.setSave_table(resourceMapper.findResoureByResource_name(attribute_values.getResource_name()).getSave_table());
		log.info("加密前的password："+password);
		String encryptedPassword = passwordEncoder.encode(password);
		log.info("加密后的password："+encryptedPassword);
		log.info("加密前后比较："+passwordEncoder.matches(password,encryptedPassword));
		attribute_values.setAttribute_key("password");
		attribute_values.setValue(encryptedPassword);
		attribute_valuesMapper.updateAttribute_values(attribute_values);
	}
	
	/**
	 * POST /account/change-password : changes the current user's password
	 *
	 * @param password
	 *            the new password
	 * @throws InvalidPasswordException
	 *             400 (Bad Request) if the new password is incorrect
	 */
	@GetMapping(path = "/account/validate-password")
	@Timed
	@ApiOperation(value = "验证当前登录用户的密码", httpMethod = "GET", notes = "验证当前登录用户的密码，无权限控制")
	@ApiParam(required = true, name = "password", value = "传入密码直接验证")
	public ResponseEntity<Map<String, Object>> validatePassword(@RequestParam("password") String password) {
		Map<String, Object> map = new HashMap<String, Object>();
		log.info("\n结束到的参数："+password);
		final String userLogin = SecurityUtils.getCurrentUserLogin();
		List<Attribute_values> list = attribute_valuesMapper.findUserByName("user", userLogin);
		if (list == null) {
			throw new InternalServerErrorException("User could not be found");
		}
		Map<String, Object> user = new HashMap<String, Object>();
		for (Attribute_values attribute_values : list) {
			user.put(attribute_values.getAttribute_key(), attribute_values.getValue());
		}
		boolean fur=passwordEncoder.matches(password, user.getOrDefault("password", "").toString());
		if(fur){
			map.put("msg", "密码验证正确！");
			map.put("error_code", 1);
		}else{
			map.put("msg", "密码验证错误！");
			map.put("error_code", 0);			
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	/**
	 * POST /account/reset-password/init : Send an email to reset the password
	 * of the user
	 *
	 * @param mail
	 *            the mail of the user
	 * @throws EmailNotFoundException
	 *             400 (Bad Request) if the email address is not registered
	 */
	// @PostMapping(path = "/account/reset-password/init")
	// @Timed
	// public void requestPasswordReset(@RequestBody String mail) {
	// mailService.sendPasswordResetMail(
	// usersService.requestPasswordReset(mail)
	// .orElseThrow(EmailNotFoundException::new)
	// );
	// }

	/**
	 * POST /account/reset-password/finish : Finish to reset the password of the
	 * user
	 *
	 * @param keyAndPassword
	 *            the generated key and the new password
	 * @throws InvalidPasswordException
	 *             400 (Bad Request) if the password is incorrect
	 * @throws RuntimeException
	 *             500 (Internal Server Error) if the password could not be
	 *             reset
	 */
	@PostMapping(path = "/account/reset-password/finish")
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/account/reset-password/finish--POST')")
	@ApiOperation(value = "更改用户的密码", httpMethod = "POST", notes = "更改用户的密码")
	@ApiParam(required = true, name = "username,newPassword", value = "修改用户的名称以及新密码，直接修改")
	public void finishPasswordReset(@RequestBody UsernameAndPasswordVM usernameAndPassword) {
		if (!checkPasswordLength(usernameAndPassword.getNewPassword())) {
			throw new InvalidPasswordException();
		}
		Attribute_values attribute_values = attribute_valuesMapper.findIdByName("user",
				usernameAndPassword.getUsername());
		if (attribute_values == null) {
			throw new InternalServerErrorException("User could not be found");
		}
		attribute_values.setSave_table(resourceMapper.findResoureByResource_name(attribute_values.getResource_name()).getSave_table());
		String encryptedPassword = passwordEncoder.encode(usernameAndPassword.getNewPassword());
		attribute_values.setAttribute_key("password");
		attribute_values.setValue(encryptedPassword);
		attribute_valuesMapper.updateAttribute_values(attribute_values);
	}

	private static boolean checkPasswordLength(String password) {
		return !StringUtils.isEmpty(password) && password.length() >= 4 && password.length() <= 100;
	}
	
	/**
	 * passwordEncoder.matches(b, a); 验证密码是否正确，a为加密密码，b为未加密密码
	 * passwordEncoder.encode(a);将字符串a加密
	 * 
	 */
	
}
