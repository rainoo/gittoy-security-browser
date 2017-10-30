package com.gittoy.security.browser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * MyUserDetailsService.java
 * 
 * @author GaoYu 2017年10月26日 下午8:06:58
 */
@Component
public class MyUserDetailsService implements UserDetailsService {

	private Logger logger = LoggerFactory.getLogger(getClass());

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		logger.info("登录用户名：" + username);
		// 根据用户名查找用户信息
		// 根据查找到的用户信息判断用户是否被冻结
		// AuthorityUtils.commaSeparatedStringToAuthorityList("admin")：将字符串转化为相应对象。
		String password = passwordEncoder.encode("123456");
		logger.info("数据库密码是：" + password);
		return new User(username, password,
				true, true, true, true,
				AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
	}

}

/** ===========================================================================

	自定义用户认证逻辑：
	1）处理用户信息获取逻辑：UserDetailsService
	2）处理用户校验逻辑：UserDetails
	3）处理密码加密解密：PasswrodEncoder
	
	UserDetails的四种boolean类型：
	1）isAccountNonExpired：用户账号是否过期
	2）isAccountNonLocked：账户是否被锁定（用户因为长期不登录或密码尝试过多等原因账户被临时锁定、可恢复）
	3）isCredentialsNonExpired：用户凭证（密码）是否过期
	4）isEnabled：用户是否失效（用户账户被逻辑删除的情况，不可恢复）
	
	加密：org.springframework.security.crypto.password.PasswordEncoder.encode()
	比对：Spring Security去调用的代码：PasswordEncoder.matches()

============================================================================= */