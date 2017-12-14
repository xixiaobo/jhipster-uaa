package com.hcycom.jhipster.web.rest;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
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
import com.hcycom.jhipster.domain.User;
import com.hcycom.jhipster.security.AuthoritiesConstants;
import com.hcycom.jhipster.service.UserService;
import com.hcycom.jhipster.web.rest.errors.BadRequestAlertException;
import com.hcycom.jhipster.web.rest.errors.EmailAlreadyUsedException;
import com.hcycom.jhipster.web.rest.errors.LoginAlreadyUsedException;
import com.hcycom.jhipster.web.rest.util.HeaderUtil;
import com.hcycom.jhipster.web.rest.util.PaginationUtil;

import io.github.jhipster.web.util.ResponseUtil;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;

/**
 * REST controller for managing users.
 * <p>
 * This class accesses the User entity, and needs to fetch its collection of
 * authorities.
 * <p>
 * For a normal use-case, it would be better to have an eager relationship
 * between User and Authority, and send everything to the client side: there
 * would be no View Model and DTO, a lot less code, and an outer-join which
 * would be good for performance.
 * <p>
 * We use a View Model and a DTO for 3 reasons:
 * <ul>
 * <li>We want to keep a lazy association between the user and the authorities,
 * because people will quite often do relationships with the user, and we don't
 * want them to get the authorities all the time for nothing (for performance
 * reasons). This is the #1 goal: we should not impact our users' application
 * because of this use-case.</li>
 * <li>Not having an outer join causes n+1 requests to the database. This is not
 * a real issue as we have by default a second-level cache. This means on the
 * first HTTP call we do the n+1 requests, but then all authorities come from
 * the cache, so in fact it's much better than doing an outer join (which will
 * get lots of data from the database, for each HTTP call).</li>
 * <li>As this manages users, for security reasons, we'd rather have a DTO
 * layer.</li>
 * </ul>
 * <p>
 * Another option would be to have a specific JPA entity graph to handle this
 * case.
 */
@RestController
@RequestMapping("/api")
@Api(tags = { "用户管理" })
public class UserResource {

	private final Logger log = LoggerFactory.getLogger(UserResource.class);

	private final UserService userService;

	public UserResource(UserService userService) {

		this.userService = userService;
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
	@Secured(AuthoritiesConstants.ADMIN)
	@ApiOperation(value = "新增用户", notes = "新增用户已经激活", httpMethod = "POST")
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/users_post')")
	@ApiParam(required = true, name = "username,sex,phone,password,name_cn,head_image,email,authorities", value = "需要传入的这些值,其他值为空，authorities为角色名称数组")
	public ResponseEntity<User> createUser(@Valid @RequestBody User user) throws URISyntaxException {
		log.debug("REST request to save User : {}", user);

		if (userService.findeUserByName(user.getUsername().toLowerCase()).isPresent()) {
			throw new LoginAlreadyUsedException();
		} else {
			if (user.getPassword() == null || user.getPassword().equals("")) {
				user.setPassword("hcy123");
			}
			User newUser = userService.createUser(user);
			return ResponseEntity.created(new URI("/api/users/" + newUser.getUsername()))
					.headers(HeaderUtil.createAlert("userManagement.created", newUser.getUsername())).body(newUser);
		}
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
	@Secured(AuthoritiesConstants.ADMIN)
	@ApiOperation(value = "修改用户", notes = "修改用户所有信息", httpMethod = "PUT")
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/users_PUT')")
	@ApiParam(required = true, name = "username,sex,phone,password,name_cn,head_image,email,authorities", value = "需要传入的这些值,其他值为空，authorities为角色名称数组")
	public ResponseEntity<User> updateUser(@Valid @RequestBody User user) {
		log.debug("REST request to update User : {}", user);
		Optional<User> updatedUser;
		User user2 = userService.findeUserByName(user.getUsername()).orElse(null);
		if (user2.getUsername() != null && user2.getId() == user.getId()) {
			throw new BadRequestAlertException("用户名已存在", "userManagement", "idexists");
		} else {
			updatedUser = userService.updateUser(user);
		}

		return ResponseUtil.wrapOrNotFound(updatedUser,
				HeaderUtil.createAlert("userManagement.updated", user.getUsername()));
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
	public ResponseEntity<List<User>> getAllUsers(@ApiParam Pageable pageable) {
		final Page<User> page = userService.getAllManagedUsers(pageable);
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
		return userService.getAuthorities();
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
	public ResponseEntity<User> getUser(@PathVariable String login) {
		log.debug("REST request to get User : {}", login);
		return ResponseUtil.wrapOrNotFound(userService.getUserWithAuthoritiesByLogin(login));
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
	@Secured(AuthoritiesConstants.ADMIN)
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/users/{login}_DELETE')")
	@ApiOperation(value = "删除用户，根据用户名", httpMethod = "DELETE", notes = "删除用户所有信息，login为用户名称")
	@ApiParam(name = "login", value = "参数类型为String,是用户的名称", required = true)
	public ResponseEntity<Void> deleteUser(@PathVariable String login) {
		log.debug("REST request to delete User: {}", login);
		userService.deleteUser(login);
		return ResponseEntity.ok().headers(HeaderUtil.createAlert("userManagement.deleted", login)).build();
	}

	@DeleteMapping("/users/{id}")
	@Timed
	@Secured(AuthoritiesConstants.ADMIN)
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/users/{id}_DELETE')")
	@ApiOperation(value = "删除用户，根据用户id", notes = "删除用户所有信息，根据用户的id", httpMethod = "DELETE")
	@ApiParam(name = "id", value = "参数类型为String,为用户的id", required = true)
	public ResponseEntity<Void> deleteUserByid(@PathVariable String id) {
		log.debug("REST request to delete User: {}", id);
		User user = userService.getUserWithAuthoritiesById(id).orElse(null);
		userService.deleteUserById(id);
		return ResponseEntity.ok().headers(HeaderUtil.createAlert("userManagement.deleted", user.getUsername()))
				.build();
	}

	@DeleteMapping("/usersByMore")
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/usersByMore')")
	@ApiOperation(value = "删除多个用户", httpMethod = "DELETE", notes = "删除多个用户根据id数组")
	@ApiParam(name = "ids", value = "参数类型为String[],为用户id的数组", required = true)
	public ResponseEntity<Void> deleteUserByMore(@RequestBody String[] ids) {
		List<String> usernames = new ArrayList<String>();
		for (String id : ids) {
			User user = userService.getUserWithAuthoritiesById(id).orElse(null);
			usernames.add(user.getUsername());
			userService.deleteUserById(id);
		}

		return ResponseEntity.ok().headers(HeaderUtil.createAlert("userManagement.deleted", usernames.toString()))
				.build();
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
		Map<String, Object> map = new HashMap<String, Object>();
		List<User> list = userService.getAlluser();
		if (list.size() > 0) {
			map.put("allUser", list);
			map.put("msg", "成功获取所有用户！");
			map.put("error_code", 1);
		} else {
			map.put("msg", "获取所有用户失败或所有用户为空！");
			map.put("error_code", 1);
		}

		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
}
