package com.hcycom.jhipster.web.rest;

import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.codahale.metrics.annotation.Timed;
import com.hcycom.jhipster.domain.User;
import com.hcycom.jhipster.security.SecurityUtils;
import com.hcycom.jhipster.service.UserService;
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


    private final UserService userService;


    public AccountResource( UserService usersService) {

        this.userService = usersService;
    }

    /**
    * POST  /register : register the user.
    *
    * @param managedUserVM the managed user View Model
    * @throws InvalidPasswordException 400 (Bad Request) if the password is incorrect
    * @throws EmailAlreadyUsedException 400 (Bad Request) if the email is already used
    * @throws LoginAlreadyUsedException 400 (Bad Request) if the login is already used
    */
    @PostMapping("/register")
    @Timed
    @ResponseStatus(HttpStatus.CREATED)
    @ApiOperation(value = "注册用户", notes = "新增用户未激活",httpMethod="POST")
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/register')")
    @ApiParam(required=true,name="username,sex,phone,password,name_cn,head_image,email,authorities",value="需要传入的这些值,其他值为空，authorities为角色名称数组")
    public void registerAccount(@Valid @RequestBody User user) {
        if (!checkPasswordLength(user.getPassword())) {
            throw new InvalidPasswordException();
        }
        userService.findeUserByName(user.getUsername().toLowerCase()).ifPresent(u -> {throw new LoginAlreadyUsedException();});
        User user1 = userService.registerUser(user);
    }

    /**
    * GET  /activate : 激活已注册用户
    *
    * @param key the activation key
    * @throws RuntimeException 500 (Internal Server Error) if the user couldn't be activated
    */
    @GetMapping("/activate")
    @Timed
    @ApiOperation(value = "激活用户", notes = "将未激活或用户激活" ,httpMethod="GET")
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/activate')")
    @ApiParam(required=true,name="username",value="传入要激活的用户名")
    public void activateAccount(@RequestParam(value = "username") String username) {
    	User user2=new User();
    	user2.setUsername(username);
        Optional<User> user = userService.activateRegistration(user2);
        if (!user.isPresent()) {
            throw new InternalServerErrorException("No user was found for this reset key");
        };
    }

    /**
    * GET  /authenticate : check if the user is authenticated, and return its login.
    *
    * @param request the HTTP request
    * @return the login if the user is authenticated
    */
    @GetMapping("/authenticate")
    @Timed
    @ApiOperation(value = "检测是否有ouath2秘钥",httpMethod="GET", notes = "检查用户是否经过身份验证，并返回其登录。")
    public String isAuthenticated(HttpServletRequest request) {
        log.debug("REST request to check if the current user is authenticated");
        return request.getRemoteUser();
    }

    /**
    * GET  /account : get the current user.
    *
    * @return the current user
    * @throws RuntimeException 500 (Internal Server Error) if the user couldn't be returned
    */
    @GetMapping("/account")
    @Timed
    @ApiOperation(value = "获取当前登录用户信息",httpMethod="GET", notes = "获取当前登录用户信息。")
    public User getAccount() {
        return Optional.ofNullable(userService.getUserWithAuthorities())
            .orElseThrow(() -> new InternalServerErrorException("User could not be found"));
    }

    /**
    * POST  /account : update the current user information.
    *
    * @param userDTO the current user information
    * @throws EmailAlreadyUsedException 400 (Bad Request) if the email is already used
    * @throws RuntimeException 500 (Internal Server Error) if the user login wasn't found
    */
    @PostMapping("/account")
    @Timed
    @ApiOperation(value = "更新当前登录用户信息",httpMethod="POST", notes = "仅更新当前登录用户基础信息。")
    @ApiParam(required=true,name="name_cn,phone,email",value="仅修改三个值，其他值为空")
    public void saveAccount(@Valid @RequestBody User user) {
        final String userLogin = SecurityUtils.getCurrentUserLogin();
        Optional<User> user1 = userService.findeUserByName(userLogin);
        if (!user1.isPresent()) {
            throw new InternalServerErrorException("User could not be found");
        }
        userService.updateUser(user.getName_cn(), user.getPhone(), user.getEmail());
   }

    /**
    * POST  /account/change-password : changes the current user's password
    *
    * @param password the new password
    * @throws InvalidPasswordException 400 (Bad Request) if the new password is incorrect
    */
    @PostMapping(path = "/account/change-password")
    @Timed
    @ApiOperation(value = "更改当前登录用户的密码",httpMethod="POST", notes = "更改当前登录用户的密码。")
    @ApiParam(required=true,name="password",value="传入新密码直接修改")
    public void changePassword(@RequestBody String password) {
        if (!checkPasswordLength(password)) {
            throw new InvalidPasswordException();
        }
        userService.changePassword(password);
   }

    /**
    * POST   /account/reset-password/init : Send an email to reset the password of the user
    *
    * @param mail the mail of the user
    * @throws EmailNotFoundException 400 (Bad Request) if the email address is not registered
    */
//    @PostMapping(path = "/account/reset-password/init")
//    @Timed
//    public void requestPasswordReset(@RequestBody String mail) {
//       mailService.sendPasswordResetMail(
//           usersService.requestPasswordReset(mail)
//               .orElseThrow(EmailNotFoundException::new)
//       );
//    }

    /**
    * POST   /account/reset-password/finish : Finish to reset the password of the user
    *
    * @param keyAndPassword the generated key and the new password
    * @throws InvalidPasswordException 400 (Bad Request) if the password is incorrect
    * @throws RuntimeException 500 (Internal Server Error) if the password could not be reset
    */
    @PostMapping(path = "/account/reset-password/finish")
    @Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'jhipsteruaa/api/account/reset-password/finish')")
    @ApiOperation(value = "更改用户的密码",httpMethod="POST", notes = "更改用户的密码。")
    @ApiParam(required=true,name="username,newPassword",value="修改用户的名称以及新密码，直接修改")
    public void finishPasswordReset(@RequestBody UsernameAndPasswordVM usernameAndPassword) {
        if (!checkPasswordLength(usernameAndPassword.getNewPassword())) {
            throw new InvalidPasswordException();
        }
        Optional<User> user =
            userService.completePasswordReset(usernameAndPassword.getNewPassword(), usernameAndPassword.getUsername());

        if (!user.isPresent()) {
            throw new InternalServerErrorException("No user was found for this reset key");
        }
    }

    private static boolean checkPasswordLength(String password) {
        return !StringUtils.isEmpty(password) &&
            password.length() >= 4 &&
            password.length() <= 100;
    }
}
