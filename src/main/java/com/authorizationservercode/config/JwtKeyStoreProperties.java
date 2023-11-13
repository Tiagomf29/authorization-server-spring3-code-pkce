package com.authorizationservercode.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Validated
@Component
@ConfigurationProperties("authorization.server.jwt.keystore")
public class JwtKeyStoreProperties {

	private Resource jksLocation;	
	private String password;	
	private String keypairAlias;

}
