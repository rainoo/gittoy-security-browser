package com.gittoy.security.browser;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.gittoy.security.browser.support.SimpleResponse;
import com.gittoy.security.core.properties.SecurityProperties;

/**
 * BrowserSecurityController.java
 *
 * @author GaoYu 2017年10月27日 下午1:12:08
 */
@RestController
public class BrowserSecurityController {

	private Logger logger = LoggerFactory.getLogger(this.getClass());

	// 做判断：引发跳转的是HTML还是非HTML，把当前的引发跳转的请求缓存到Session里。
	private RequestCache requestCache = new HttpSessionRequestCache();

	// 跳转用
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	@Autowired
	private SecurityProperties securityProperties;

	/**
	 * 当需要身份认证时跳转到这里。
	 * 
	 * @param request
	 * @param response
	 * @return
	 * @throws IOException
	 */
	@RequestMapping("/authentication/require")
	@ResponseStatus(code = HttpStatus.UNAUTHORIZED)
	public SimpleResponse reqireAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws IOException {

		SavedRequest savedRequest = requestCache.getRequest(request, response);

		if (savedRequest != null) {

			// targetUrl为引发跳转的Url的字符串
			String targetUrl = savedRequest.getRedirectUrl();

			// 判断引发跳转的请求是否是html，是的话跳转到登录页面，否则提示错误信息。
			if (StringUtils.endsWith(targetUrl, "html")) {
				// 请求跳转
				redirectStrategy.sendRedirect(request, response, securityProperties.getBrowser().getLoginPage());
			}
			logger.info("引发跳转的请求是： " + targetUrl);
		}

		return new SimpleResponse("访问的服务需要身份认证，请引导用户到登录页");
	}
}
