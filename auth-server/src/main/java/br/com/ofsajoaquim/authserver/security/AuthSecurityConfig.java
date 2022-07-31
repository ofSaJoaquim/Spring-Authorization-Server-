package br.com.ofsajoaquim.authserver.security;

import java.io.InputStream;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import br.com.ofsajoaquim.authserver.security.AuthProperties.JksProperties;

@EnableWebSecurity
@Configuration
public class AuthSecurityConfig {

	//Metódo padrão 
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception{
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		return http.formLogin(Customizer.withDefaults()).build();
	}
	
	//Metódo da regra de acesso dos endspoints
	@Bean	
	public SecurityFilterChain authFilterChain(HttpSecurity http) throws Exception{
		http.authorizeRequests().anyRequest().authenticated();
		return http.formLogin(Customizer.withDefaults()).build();
	}
	
	//Metódo das credenciais dos clients oauth2
	//700c1f1d-c947-4e4d-9791-4a4d625a1daa
	@Bean
	public RegisteredClientRepository setFilterChains(PasswordEncoder passwordEncoder) throws Exception{
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
	
	//Metódo que set o responsável pela geração do token
	@Bean
	public ProviderSettings providerSettings(AuthProperties authProperties ) {
		return ProviderSettings.builder()
				.issuer(authProperties.getProviderUri())
				.build();
	}
	
	
	//Metódo responsável pela leitura do arquivo .jks e retornando objeto com as chaves
	@Bean
	public	JWKSet jwkSet(AuthProperties authProperties) throws Exception{
		final JksProperties jksProperties = authProperties.getJks();		
		final String jksPath = jksProperties.getPath();
		final InputStream inputStream = new ClassPathResource(jksPath).getInputStream();
		
		final KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(inputStream,jksProperties.getStorepass().toCharArray());
		RSAKey rsaKey = RSAKey.load(keyStore, jksProperties.getAlias(), 
				jksProperties.getKeypass().toCharArray());
		return new JWKSet(rsaKey);
	}
	
	@Bean
	public JWKSource<SecurityContext>jwkSource(JWKSet jwkSet){
		return ((jwkSelector,securityContext) -> jwkSelector.select(jwkSet));
	}
	
	
	//Bean para assinar
	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext>jwkSource) {
		 return new NimbusJwtEncoder(jwkSource); 
	}
	
}
