package com.gittoy.security.browser;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import com.gittoy.security.core.authentication.AbstractChannelSecurityConfig;
import com.gittoy.security.core.authentication.mobile.SmsCodeAuthenticationSecurityConfig;
import com.gittoy.security.core.properties.SecurityConstants;
import com.gittoy.security.core.properties.SecurityProperties;
import com.gittoy.security.core.validate.code.ValidateCodeSecurityConfig;

/**
 * BrowserSecurityConfig.java
 *
 * @author GaoYu 2017年10月26日 下午3:46:23
 */
@Configuration
public class BrowserSecurityConfig extends AbstractChannelSecurityConfig {

	@Autowired
	private SecurityProperties securityProperties;

	@Autowired
	private DataSource dataSource;

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig;

	@Autowired
	private ValidateCodeSecurityConfig validateCodeSecurityConfig;

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		applyPasswordAuthenticationConfig(http);

		http.apply(validateCodeSecurityConfig) // 校验码相关配置
				.and()
			.apply(smsCodeAuthenticationSecurityConfig) // 短信相关配置
				.and()
			.rememberMe() // 浏览器特有配置：记住我
				.tokenRepository(persistentTokenRepository())
				.tokenValiditySeconds(securityProperties.getBrowser().getRememberMeSeconds())
				.userDetailsService(userDetailsService)
				.and()
			.authorizeRequests() // 浏览器特有配置：授权相关
				.antMatchers(
					SecurityConstants.DEFAULT_UNAUTHENTICATION_URL,
					SecurityConstants.DEFAULT_LOGIN_PROCESSING_URL_MOBILE,
					securityProperties.getBrowser().getLoginPage(),
					SecurityConstants.DEFAULT_VALIDATE_CODE_URL_PREFIX + "/*")
					.permitAll()
				.anyRequest()
				.authenticated()
				.and()
			.csrf().disable();

	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public PersistentTokenRepository persistentTokenRepository() {
		JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
		tokenRepository.setDataSource(dataSource);
//		tokenRepository.setCreateTableOnStartup(true);
		return tokenRepository;
	}

}
/** ===========================================================================

	SpringSecurity核心功能：
	1：认证（你是谁）
	2：授权（你能干什么）
	3：攻击防护（防止伪造身份）
	
	实现用户名 + 密码认证：用Spring Security内部提供方案
	
	SpringSecurity基本原理：Spring Security 过滤器链
	
	认证处理流程：
	1）UsernamePasswordAuthenticationFilter：将用户名和密码及request信息封装成一个Token类
	2）AuthenticationManager：用来管理下面的类，收集循环处理挑出一个Provider。
	3）AuthenticationProvider：支持匹配某种authentication的类型，进行实际的校验逻辑。
	4）UserDetailsService：调用用户的UserDetailsService的实现Service类
	5）UserDetails：上面的Service用户实现类来获得UserDetails（多是数据库等取得的用户信息UserDetails对象）
	6）Authentication（已认证）
	
	SecurityContextPersistenceFilter: 请求过来后的过滤器链上的最前面。
	当请求进来的时候，它会检查Session里是否有SecurityContext，如果有，则拿出来放到线程里；
	当处理返回最后一个过它的时候，它会检查线程，如果线程里有SecurityContext，则拿出来放到Session里。
	这样，不同的请求就可以从session里拿到认证信息。
	
	绿色过滤器 -> 表单登录 | Http Basic登录
	UserName Password Authentication Filter | Basic Authentication Filter
	检查当前的请求里面是否有该过滤器所需要的信息：例如上面的例子，UserName Password Authentication Filter
	首先会检查当前是否是登录请求，如果是登录请求，则查看当前的登录请求是否携带用户名和密码信息。
	如果带了用户名和密码，则该过滤器会尝试用该用户名和密码做登录动作。如果没有带用户名和密码，则会放过去，放给下一个过滤器。
	Basic Authentication Filter则会检查请求的请求头里面是否有basic Authentication的信息，如果有的话，
	则会尝试做解码操作，取出用户名和密码来做登录操作。
	任何一个过滤器都成功完成了用户登录以后，都会在该请求上做一个标记，表示该用户认证成功。
	请求最终会到达 FilterSecurityInterceptor（橙色过滤器）上，是Spring Security过滤器链上的最后一环。
	该过滤器会决定请求是否会请求到controller的真正服务，依据则是用户的代码中（该例）的配置。
	不通过的情况下，则会抛出相应的异常（例如没有经过身份认证、没有权限的异常），该异常抛出后，
	Exception Translation Filter会捕获抛出的异常，根据抛出的异常类型，做相应的处理。
	例如登录处理则引导用户到登录页面。
	
	绿色过滤器可以配置，其他颜色不可以控制。
	
	记住我功能基本原理：
	1）浏览器认证请求 ——> UsernamePasswordAuthenticationFilter ——> 认证成功：调用RemberMeService
	2）RemberMeService会生成一个Token，并将其写入浏览器Cookie里，同时用TokenRepository，将Token写入数据库
	3）用户再通过浏览器请求服务，请求经过过滤器链会经过RememberMeAuthenticaitonFilter，会读取Cookie中的Token
	4）读出之后，会将Token信息交给RemberMeService，该服务用TokenRepository去数据库中查找Token
	5）如果数据库中有记录，则会把对应的用户名信息取出来，然后去调用UserDetailsService，去获取用户的信息
	6）取到的用户信息放到SecurityContext，完成登录动作

============================================================================= */