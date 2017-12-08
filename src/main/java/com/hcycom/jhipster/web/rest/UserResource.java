package com.hcycom.jhipster.web.rest;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
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

import io.github.jhipster.web.util.ResponseUtil;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

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
	@ApiOperation(value = "新增用户", notes = "新增用户以经激活")
	public ResponseEntity<User> createUser(@Valid @RequestBody User user) throws URISyntaxException {
		log.debug("REST request to save User : {}", user);

		if (userService.findeUserByName(user.getUsername().toLowerCase()).isPresent()) {
			throw new LoginAlreadyUsedException();
		} else {
			User newUser = userService.registerUser(user);
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
	@ApiOperation(value = "修改用户", notes = "修改用户")
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
	// @GetMapping("/users")
	// @Timed
	// public ResponseEntity<List<User>> getAllUsers(@ApiParam Pageable
	// pageable) {
	// final Page<User> page = userService.getAllManagedUsers(pageable);
	// HttpHeaders headers = PaginationUtil.generatePaginationHttpHeaders(page,
	// "/api/users");
	// return new ResponseEntity<>(page.getContent(), headers, HttpStatus.OK);
	// }

	/**
	 * @return a string list of the all of the roles
	 */
	@GetMapping("/users/authorities")
	@Timed
	@Secured(AuthoritiesConstants.ADMIN)
	@ApiOperation(value = "获取角色名称", notes = "获取所有的角色名称")
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
	@ApiOperation(value = "获取用户", notes = "获取用户所有信息")
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
	@ApiOperation(value = "删除用户", notes = "删除用户所有信息")
	public ResponseEntity<Void> deleteUser(@PathVariable String login) {
		log.debug("REST request to delete User: {}", login);
		userService.deleteUser(login);
		return ResponseEntity.ok().headers(HeaderUtil.createAlert("userManagement.deleted", login)).build();
	}
	
	/**
	 * DELETE /users/:login : delete the "login" User.
	 *
	 * @param login
	 *            the login of the user to delete
	 * @return the ResponseEntity with status 200 (OK)
	 */
	@GetMapping("/allusers")
	@Timed
	@Secured(AuthoritiesConstants.ADMIN)
	@ApiOperation(value = "获取所有用户", notes = "获取所有用户所有信息")
	public ResponseEntity<Map<String, Object>> getAllUser() {
		Map<String, Object> map =new HashMap<String, Object>();
		List<User> list=userService.getAlluser();
		if(list.size()>0){
			map.put("allUser", list);
			map.put("msg", "成功获取所有用户！");
			map.put("error_code", 1);
		}else {
			map.put("msg", "获取所有用户失败或所有用户为空！");
			map.put("error_code", 1);
		}
		
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
}
