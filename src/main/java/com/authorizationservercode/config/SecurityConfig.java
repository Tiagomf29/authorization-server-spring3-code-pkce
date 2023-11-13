package com.authorizationservercode.config;

import java.io.InputStream;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	@Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{		
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
		return httpSecurity.formLogin(Customizer.withDefaults()).build();
	}
    
    @Bean
    AuthorizationServerSettings authorizationServerSettings(AuthorizationProperties authorizationProperties) {
    	authorizationProperties.setPrividerUrl("http://localhost:8088");
    	return AuthorizationServerSettings.builder()
    			.issuer(authorizationProperties.getPrividerUrl())
    			.build();
    }

    @Bean
    PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }

    @Bean
    InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.builder().username("tiago")
                .password(passwordEncoder().encode("123456"))
                .roles("READ")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
    
    @Bean
    RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {     	
    	RegisteredClient registeredClient = RegisteredClient
    										.withId("1")
    										.clientId("teste-oauth")
    										.clientSecret(passwordEncoder.encode("123"))
    										.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
    										.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
    										.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
    										.scopes(ConsumerGrantType.scopeds())
    										.tokenSettings(TokenSettings.builder()
    														.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED) // opaque Token    														
    														.accessTokenTimeToLive(Duration.ofMinutes(30))    																								
    														.build())
    										.redirectUri("http://127.0.0.1:8088/authorize")
    										.clientSettings(ClientSettings.builder()
    												.requireAuthorizationConsent(false).build())
    										.build();
    										
    	return new InMemoryRegisteredClientRepository(Arrays.asList(registeredClient));
    }
    
    @Bean
    JWKSource<SecurityContext> jwkSource(JwtKeyStoreProperties properties) throws Exception {
        char[] keyStorePass = properties.getPassword().toCharArray();
        String keypairAlias = properties.getKeypairAlias();

        Resource jksLocation = properties.getJksLocation();
        InputStream inputStream = jksLocation.getInputStream();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(inputStream, keyStorePass);

        RSAKey rsaKey = RSAKey.load(keyStore, keypairAlias, keyStorePass);

        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }
                  
}
