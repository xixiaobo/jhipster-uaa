package com.hcycom.jhipster.service;

import java.beans.BeanInfo;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.hcycom.jhipster.domain.Attribute;
import com.hcycom.jhipster.domain.Attribute_values;
import com.hcycom.jhipster.domain.Authority;
import com.hcycom.jhipster.domain.Resource;
import com.hcycom.jhipster.domain.Role;
import com.hcycom.jhipster.domain.User;
import com.hcycom.jhipster.security.SecurityUtils;
import com.hcycom.jhipster.service.mapper.AttributeMapper;
import com.hcycom.jhipster.service.mapper.Attribute_valuesMapper;
import com.hcycom.jhipster.service.mapper.ResourceMapper;
import com.hcycom.jhipster.service.mapper.RoleMapper;

import net.sf.json.JSONObject;

/**
 * Service class for managing users.
 */
@Service
public class UserService {

	private final Logger log = LoggerFactory.getLogger(UserService.class);

	// private final Attribute_valuesMapper attribute_valuesMapper;
	// private final AttributeMapper attributeMapper;
	// private final ResourceMapper resourceMapper;
	// private final RoleMapper roleMapper;

	@Autowired
	private Attribute_valuesMapper attribute_valuesMapper;
	@Autowired
	private AttributeMapper attributeMapper;
	@Autowired
	private ResourceMapper resourceMapper;
	@Autowired
	private RoleMapper roleMapper;

	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
	//
	// private final PasswordEncoder passwordEncoder;

	// public UserService(RoleMapper roleMapper, ResourceMapper resourceMapper,
	// AttributeMapper attributeMapper,
	// Attribute_valuesMapper attribute_valuesMapper, PasswordEncoder
	// passwordEncoder) {
	// this.attribute_valuesMapper = attribute_valuesMapper;
	// this.attributeMapper = attributeMapper;
	// this.resourceMapper = resourceMapper;
	// this.roleMapper = roleMapper;
	// this.passwordEncoder = passwordEncoder;
	// }

	// public UserService(PasswordEncoder passwordEncoder) {
	// this.passwordEncoder = passwordEncoder;
	// }

	/**
	 * 根据登录名找到用户信息
	 * 
	 * @param username
	 * @return
	 */
	public Optional<User> findeUserByName(String username) {
		User user = new User();
		Resource resource = resourceMapper.findResoureBySave_table("user");
		List<Attribute_values> list = attribute_valuesMapper.findUserByName(resource.getResource_name(), username);
		Map map = new HashMap();
		for (Attribute_values attribute_values : list) {
			map.put(attribute_values.getAttribute_key(), attribute_values.getValue());
		}
		JSONObject json = JSONObject.fromObject(map);
		user = (User) JSONObject.toBean(json, User.class);
		Optional<User> optional = Optional.ofNullable(user);
		return optional;
	}

	/**
	 * 根据用户信息中的roles值查询用户拥有的权限
	 * 
	 * @param roles
	 * @return
	 */
	public List<GrantedAuthority> getUsersAuthority(String roles) {
		List<Role> rolelist = new ArrayList<Role>();
		String[] rolesids = roles.split(",");
		for (String rolesid : rolesids) {
			rolelist.add(roleMapper.getUsersAuthority(rolesid));
		}
		List<GrantedAuthority> grantedAuthorities = rolelist.stream()
				.map(role -> new SimpleGrantedAuthority(role.getRole_name())).collect(Collectors.toList());

		return grantedAuthorities;
	}

	/**
	 * 激活注册
	 * 
	 * @param key
	 * @return
	 */
	public Optional<User> activateRegistration(User user) {
		log.debug("Activating user for activation key {}", user);
		Resource resource = resourceMapper.findResoureBySave_table("user");
		List<Attribute_values> list = attribute_valuesMapper.findUserByName(resource.getResource_name(),
				user.getUsername());
		Map map = new HashMap();
		for (Attribute_values attribute_values : list) {
			map.put(attribute_values.getAttribute_key(), attribute_values.getValue());
		}
		JSONObject json = JSONObject.fromObject(map);
		user = (User) JSONObject.toBean(json, User.class);
		Attribute_values attribute_values = new Attribute_values();
		attribute_values.setUuid(user.getId());
		attribute_values.setResource_name(resource.getResource_name());
		attribute_values.setAttribute_key("status");
		attribute_values.setValue("1");
		attribute_valuesMapper.updateAttribute_values(attribute_values);
		Optional<User> optional = Optional.ofNullable(user);
		return optional;

	}

	/**
	 * 密码重置
	 * 
	 * @param newPassword
	 * @param key
	 * @return
	 */
	public Optional<User> completePasswordReset(String newPassword, String username) {
		User user = new User();
		Resource resource = resourceMapper.findResoureBySave_table("user");
		List<Attribute_values> list = attribute_valuesMapper.findUserByName(resource.getResource_name(), username);
		Map map = new HashMap();
		for (Attribute_values attribute_values : list) {
			map.put(attribute_values.getAttribute_key(), attribute_values.getValue());
		}
		JSONObject json = JSONObject.fromObject(map);
		user = (User) JSONObject.toBean(json, User.class);
		Attribute_values attribute_values = new Attribute_values();
		attribute_values.setUuid(user.getId());
		attribute_values.setResource_name(resource.getResource_name());
		attribute_values.setAttribute_key("password");
		attribute_values.setValue(passwordEncoder.encode(newPassword));
		attribute_valuesMapper.updateAttribute_values(attribute_values);
		Optional<User> optional = Optional.ofNullable(user);
		return optional;
	}
	//
	// public Optional<User> requestPasswordReset(String mail) {
	// return userRepository.findOneByEmailIgnoreCase(mail)
	// .filter(User::getActivated)
	// .map(user -> {
	// user.setResetKey(RandomUtil.generateResetKey());
	// user.setResetDate(Instant.now());
	// return user;
	// });
	// }
	//

	/**
	 * 登记用户
	 * 
	 * @param userDTO
	 * @return
	 */
	public User registerUser(User user) {
		String encryptedPassword = passwordEncoder.encode(user.getPassword());
		String uuid = UUID.randomUUID().toString().replaceAll("-", "");
		Set<String> set = user.getAuthorities();
		List<Integer> list=new ArrayList<Integer>();
		for (String string : set) {
			Role role=new Role();
			role=roleMapper.getRoleByRole_name(string);
			list.add(role.getUuid());
		}
		String roles = "";
		for (int string : list) {
			roles+=string+",";
		}
		roles=roles.substring(0,roles.length()-1);
		user.setRoles(roles);
		user.setId(uuid);
		user.setStatus(0);
		Map<String, Object> map = BeanMap(user);
		Resource resource = resourceMapper.findResoureBySave_table("user");
		Attribute attribute = new Attribute();
		attribute.setResource_name_foreign(resource.getResource_name());
		List<Attribute> attributes = attributeMapper.findAttributeByResource_name(attribute);
		for (Attribute attribute2 : attributes) {
			Attribute_values attribute_values = new Attribute_values();
			attribute_values.setUuid(uuid);
			attribute_values.setResource_name(resource.getResource_name());
			attribute_values.setAttribute_key(attribute2.getAttribute_key());
			attribute_values.setValue((String) map.get(attribute2.getAttribute_key()));
			attribute_valuesMapper.addAttribute_values(attribute_values);
		}

		log.debug("Created Information for User: {}", user);
		return user;
	}

	/**
	 * 创建用户
	 * 
	 * @param userDTO
	 * @return
	 */
	public User createUser(User user) {
		String encryptedPassword = passwordEncoder.encode(user.getPassword());
		String uuid = UUID.randomUUID().toString().replaceAll("-", "");
		Set<String> set = user.getAuthorities();
		List<Integer> list=new ArrayList<Integer>();
		for (String string : set) {
			Role role=new Role();
			role=roleMapper.getRoleByRole_name(string);
			list.add(role.getUuid());
		}
		String roles = "";
		for (int string : list) {
			roles+=string+",";
		}
		roles=roles.substring(0,roles.length()-1);
		user.setRoles(roles);
		user.setId(uuid);
		user.setStatus(1);
		Map<String, Object> map = BeanMap(user);
		Resource resource = resourceMapper.findResoureBySave_table("user");
		Attribute attribute = new Attribute();
		attribute.setResource_name_foreign(resource.getResource_name());
		List<Attribute> attributes = attributeMapper.findAttributeByResource_name(attribute);
		for (Attribute attribute2 : attributes) {
			Attribute_values attribute_values = new Attribute_values();
			attribute_values.setUuid(uuid);
			attribute_values.setResource_name(resource.getResource_name());
			attribute_values.setAttribute_key(attribute2.getAttribute_key());
			attribute_values.setValue((String) map.get(attribute2.getAttribute_key()));
			attribute_valuesMapper.addAttribute_values(attribute_values);
		}
		log.debug("Created Information for User: {}", user);
		return user;
	}

	/**
	 * 修改用户的基本信息（name_cn、phone、sex、head_image、email）
	 *
	 * @param firstName
	 *            first name of user
	 * @param lastName
	 *            last name of user
	 * @param email
	 *            email id of user
	 * @param langKey
	 *            language key
	 * @param imageUrl
	 *            image URL of user
	 */
	public void updateUser(String name_cn, String phone, String sex, String head_image, String email) {
		User user = new User();
		Resource resource = resourceMapper.findResoureBySave_table("user");
		List<Attribute_values> list = attribute_valuesMapper.findUserByName(resource.getResource_name(),
				SecurityUtils.getCurrentUserLogin());
		Map map = new HashMap();
		for (Attribute_values attribute_values : list) {
			map.put(attribute_values.getAttribute_key(), attribute_values.getValue());
		}
		JSONObject json = JSONObject.fromObject(map);
		user = (User) JSONObject.toBean(json, User.class);
		user.setName_cn(name_cn);
		user.setPhone(phone);
		user.setHead_image(head_image);
		user.setSex(sex);
		user.setEmail(email);
		Map<String, Object> usermap = BeanMap(user);
		Attribute attribute = new Attribute();
		attribute.setResource_name_foreign(resource.getResource_name());
		List<Attribute> attributes = attributeMapper.findAttributeByResource_name(attribute);
		for (Attribute attribute2 : attributes) {
			Attribute_values attribute_values = new Attribute_values();
			attribute_values.setUuid(user.getId());
			attribute_values.setResource_name(resource.getResource_name());
			attribute_values.setAttribute_key(attribute2.getAttribute_key());
			attribute_values.setValue((String) usermap.get(attribute2.getAttribute_key()));
			attribute_valuesMapper.updateAttribute_values(attribute_values);
		}

	}

	/**
	 * 修改指定用户的所有信息.
	 *
	 * @param userDTO
	 *            user to update
	 * @return updated user
	 */
	public Optional<User> updateUser(User user) {
		Resource resource = resourceMapper.findResoureBySave_table("user");
		Map<String, Object> usermap = BeanMap(user);
		Attribute attribute = new Attribute();
		attribute.setResource_name_foreign(resource.getResource_name());
		List<Attribute> attributes = attributeMapper.findAttributeByResource_name(attribute);
		for (Attribute attribute2 : attributes) {
			Attribute_values attribute_values = new Attribute_values();
			attribute_values.setUuid(user.getId());
			attribute_values.setResource_name(resource.getResource_name());
			attribute_values.setAttribute_key(attribute2.getAttribute_key());
			attribute_values.setValue((String) usermap.get(attribute2.getAttribute_key()));
			attribute_valuesMapper.updateAttribute_values(attribute_values);
		}

		Optional<User> optional = Optional.ofNullable(user);
		return optional;
	}

	/**
	 * 根据用户名删除用户
	 * 
	 * @param login
	 */
	public void deleteUser(String login) {
		User user = new User();
		Resource resource = resourceMapper.findResoureBySave_table("user");
		List<Attribute_values> list = attribute_valuesMapper.findUserByName(resource.getResource_name(), login);
		Map map = new HashMap();
		for (Attribute_values attribute_values : list) {
			map.put(attribute_values.getAttribute_key(), attribute_values.getValue());
		}
		JSONObject json = JSONObject.fromObject(map);
		user = (User) JSONObject.toBean(json, User.class);
		Attribute_values attribute_values = new Attribute_values();
		attribute_values.setResource_name(resource.getResource_name());
		attribute_values.setUuid(user.getId());
		attribute_valuesMapper.deleteAttribute_values(attribute_values);
	}

	/**
	 * 修改密码
	 * 
	 * @param password
	 */
	public void changePassword(String password) {
		User user = new User();
		Resource resource = resourceMapper.findResoureBySave_table("user");
		List<Attribute_values> list = attribute_valuesMapper.findUserByName(resource.getResource_name(),
				SecurityUtils.getCurrentUserLogin());
		Map map = new HashMap();
		for (Attribute_values attribute_values : list) {
			map.put(attribute_values.getAttribute_key(), attribute_values.getValue());
		}
		JSONObject json = JSONObject.fromObject(map);
		user = (User) JSONObject.toBean(json, User.class);
		String encryptedPassword = passwordEncoder.encode(password);
		user.setPassword(encryptedPassword);
		Attribute_values attribute_values = new Attribute_values();
		attribute_values.setUuid(user.getId());
		attribute_values.setResource_name(resource.getResource_name());
		attribute_values.setAttribute_key("password");
		attribute_values.setValue(encryptedPassword);
		attribute_valuesMapper.updateAttribute_values(attribute_values);
	}

	// @Transactional(readOnly = true)
	// public Page<User> getAllManagedUsers(Pageable pageable) {
	// return userRepository.findAllByLoginNot(pageable,
	// Constants.ANONYMOUS_USER).map(UserDTO::new);
	// }

	@Transactional(readOnly = true)
	public Optional<User> getUserWithAuthoritiesByLogin(String login) {
		User user = new User();
		Resource resource = resourceMapper.findResoureBySave_table("user");
		List<Attribute_values> list = attribute_valuesMapper.findUserByName(resource.getResource_name(), login);
		Map map = new HashMap();
		for (Attribute_values attribute_values : list) {
			map.put(attribute_values.getAttribute_key(), attribute_values.getValue());
		}
		JSONObject json = JSONObject.fromObject(map);
		user = (User) JSONObject.toBean(json, User.class);
		Set<String> authorities = new HashSet<>();
		String[] rolesids = user.getRoles().split(",");
		for (String rolesid : rolesids) {
			authorities.add(roleMapper.getUsersAuthority(rolesid).getRole_name());
		}
		user.setLogin(user.getUsername());
		user.setAuthorities(authorities);

		Optional<User> optional = Optional.ofNullable(user);
		return optional;
	}

	@Transactional(readOnly = true)
	public User getUserWithAuthorities(String id) {
		User user = new User();
		Resource resource = resourceMapper.findResoureBySave_table("user");
		Attribute_values attribute_values = new Attribute_values();
		attribute_values.setResource_name(resource.getResource_name());
		attribute_values.setUuid(id);
		List<Attribute_values> list = attribute_valuesMapper.findAttribute_valuesByResource_name(attribute_values);
		Map map = new HashMap();
		for (Attribute_values attribute_values2 : list) {
			map.put(attribute_values2.getAttribute_key(), attribute_values2.getValue());
		}
		JSONObject json = JSONObject.fromObject(map);
		user = (User) JSONObject.toBean(json, User.class);
		Set<String> authorities = new HashSet<>();
		String[] rolesids = user.getRoles().split(",");
		for (String rolesid : rolesids) {
			authorities.add(roleMapper.getUsersAuthority(rolesid).getRole_name());
		}
		user.setLogin(user.getUsername());
		user.setAuthorities(authorities);
		return user;
	}

	@Transactional(readOnly = true)
	public User getUserWithAuthorities() {
		User user = new User();
		Resource resource = resourceMapper.findResoureBySave_table("user");
		List<Attribute_values> list = attribute_valuesMapper.findUserByName(resource.getResource_name(),
				SecurityUtils.getCurrentUserLogin());
		Map map = new HashMap();
		for (Attribute_values attribute_values : list) {
			map.put(attribute_values.getAttribute_key(), attribute_values.getValue());
		}
		JSONObject json = JSONObject.fromObject(map);
		user = (User) JSONObject.toBean(json, User.class);
		Set<String> authorities = new HashSet<>();
		String[] rolesids = user.getRoles().split(",");
		for (String rolesid : rolesids) {
			authorities.add(roleMapper.getUsersAuthority(rolesid).getRole_name());
		}
		user.setLogin(user.getUsername());
		user.setAuthorities(authorities);

		Optional<User> optional = Optional.ofNullable(user);
		return optional.orElse(null);
	}
	//
	// /**
	// * Not activated users should be automatically deleted after 3 days.
	// * <p>
	// * This is scheduled to get fired everyday, at 01:00 (am).
	// */
	// @Scheduled(cron = "0 0 1 * * ?")
	// public void removeNotActivatedUsers() {
	// List<User> users =
	// userRepository.findAllByActivatedIsFalseAndCreatedDateBefore(Instant.now().minus(3,
	// ChronoUnit.DAYS));
	// for (User user : users) {
	// log.debug("Deleting not activated user {}", user.getLogin());
	// userRepository.delete(user);
	// }
	// }

	/**
	 * @return a list of all the authorities
	 */
	public List<String> getAuthorities() {
		return roleMapper.getAllAuthority().stream().map(Role::getRole_name).collect(Collectors.toList());
	}
	
	
	public List<User> getAlluser(){
		List<User> users=new ArrayList<User>();
		Resource resource = resourceMapper.findResoureBySave_table("user");
		Attribute_values attribute_values=new Attribute_values();
		attribute_values.setResource_name(resource.getResource_name());
		List<Attribute_values> list = attribute_valuesMapper.findAttribute_valuesByResource_name(attribute_values);
		Map map = new HashMap();
		log.debug("alluser:"+list);
		for (Attribute_values values : list) {
			if(values.getAttribute_key().equals("id")){
				attribute_values.setUuid(values.getValue());
				List<Attribute_values> list2 = attribute_valuesMapper.findAttribute_valuesByResource_nameANDUuid(attribute_values);
				for (Attribute_values attribute_values2 : list2) {
					map.put(attribute_values2.getAttribute_key(), attribute_values2.getValue());
				}
				JSONObject json = JSONObject.fromObject(map);
				User user = (User) JSONObject.toBean(json, User.class);
				users.add(user);
			}
		}
		return users;
	}

	public static Map<String, Object> BeanMap(Object obj) {
		if (obj == null) {
			return null;
		}
		Map<String, Object> map = new HashMap<String, Object>();
		try {
			BeanInfo beanInfo = Introspector.getBeanInfo(obj.getClass());
			PropertyDescriptor[] propertyDescriptors = beanInfo.getPropertyDescriptors();
			for (PropertyDescriptor property : propertyDescriptors) {
				String key = property.getName();
				// 过滤class属性
				if (!key.equals("class")) {
					// 得到property对应的getter方法
					Method getter = property.getReadMethod();
					Object value = getter.invoke(obj);

					map.put(key, value);
				}

			}
		} catch (Exception e) {
			System.out.println("错误");
		}
		return map;
	}

}
