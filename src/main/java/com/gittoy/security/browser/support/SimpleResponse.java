package com.gittoy.security.browser.support;

/**
 * SimpleResponse.java
 *
 * @author GaoYu 2017年10月27日 下午1:48:26
 */
public class SimpleResponse {

	public SimpleResponse(Object content) {
		this.content = content;
	}

	private Object content;

	public Object getContent() {
		return content;
	}

	public void setContent(Object content) {
		this.content = content;
	}

}
