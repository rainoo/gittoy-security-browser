package com.gittoy.security.browser;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.gittoy.security.core.properties.SecurityProperties;

/**
 * BrowserSecurityConfig.java
 * 
 * SpringSecurity核心功能：
 * 1：认证（你是谁）
 * 2：授权（你能干什么）
 * 3：攻击防护（防止伪造身份）
 * 
 * 实现用户名 + 密码认证：用Spring Security内部提供方案
 * 
 * SpringSecurity基本原理：Spring Security过滤器链
 * 绿色过滤器 -> 表单登录 | Http Basic登录
 * UserName Password Authentication Filter | Basic Authentication Filter
 * 检查当前的请求里面是否有该过滤器所需要的信息：例如上面的例子，UserName Password Authentication Filter
 * 首先会检查当前是否是登录请求，如果是登录请求，则查看当前的登录请求是否携带用户名和密码信息。
 * 如果带了用户名和密码，则该过滤器会尝试用该用户名和密码做登录动作。如果没有带用户名和密码，则会放过去，放给下一个过滤器。
 * Basic Authentication Filter则会检查请求的请求头里面是否有basic Authentication的信息，如果有的话，
 * 则会尝试做解码操作，取出用户名和密码来做登录操作。
 * 任何一个过滤器都成功完成了用户登录以后，都会在该请求上做一个标记，表示该用户认证成功。
 * 请求最终会到达 FilterSecurityInterceptor（橙色过滤器）上，是Spring Security过滤器链上的最后一环。
 * 该过滤器会决定请求是否会请求到controller的真正服务，依据则是用户的代码中（该例）的配置。
 * 不通过的情况下，则会抛出相应的异常（例如没有经过身份认证、没有权限的异常），该异常抛出后，
 * Exception Translation Filter会捕获抛出的异常，根据抛出的异常类型，做相应的处理。
 * 例如登录处理则引导用户到登录页面。
 * 
 * 绿色过滤器可以配置，其他颜色不可以控制。
 *
 * @author GaoYu 2017年10月26日 下午3:46:23
 */
@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private SecurityProperties securityProperties;

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		// 表单登录指定进行身份认证方式：其它方式 http.httpBasic()
		http.formLogin()
				.loginPage("/authentication/require") // 指定登录页面
				.loginProcessingUrl("/authentication/form")
				.and() // 授权配置
				.authorizeRequests() // 对请求进行授权
				.antMatchers("/authentication/require",
						securityProperties.getBrowser().getLoginPage()).permitAll() // 匹配到该网页后不需要身份认证
				.anyRequest() // 任何请求
				.authenticated() // 都需要身份认证
				.and()
				.csrf().disable(); // 跨站防护功能去除 CSRF Token

	}
}
