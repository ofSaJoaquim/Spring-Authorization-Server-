package br.com.ofsajoaquim.authserver.security;

import java.time.Duration;
import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class AuthSecurityConfig {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception{
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		return http.formLogin(Customizer.withDefaults()).build();
	}
	
	
	@Bean	
	public SecurityFilterChain authFilterChain(HttpSecurity http) throws Exception{
		http.authorizeRequests().anyRequest().authenticated();
		return http.formLogin(Customizer.withDefaults()).build();
	}
	
	
	public RegisteredClientRepository authFilterChain(PasswordEncoder passwordEncoder) throws Exception{
		RegisteredClient awuserClient = RegisteredClient
				.withId("1")
				.clientId("awuser")
				.clientSecret(passwordEncoder.encode("123456"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope("users:read")
				.scope("users:write")
				.tokenSettings(
						TokenSettings.builder()
						.accessTokenTimeToLive(Duration.ofMinutes(5))
						.build())
				.clientSettings(ClientSettings.builder()
						.requireAuthorizationConsent(false)
						.build())
				.build()
				;
		
		return new InMemoryRegisteredClientRepository(
				Arrays.asList(awuserClient)
				
				);
	}
	
	@Bean
	public ProviderSettings providerSettings(AuthProperties authProperties ) {
		return ProviderSettings.builder()
				.issuer(authProperties.getProviderUri())
				.build();
	}
}
