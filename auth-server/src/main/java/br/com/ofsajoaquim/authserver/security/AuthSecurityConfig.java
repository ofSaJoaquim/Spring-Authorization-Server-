package br.com.ofsajoaquim.authserver.security;

import java.io.InputStream;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import br.com.ofsajoaquim.authserver.entity.UserEntity;
import br.com.ofsajoaquim.authserver.entity.UserEntity.Type;
import br.com.ofsajoaquim.authserver.entity.repository.UserRepository;
import br.com.ofsajoaquim.authserver.security.AuthProperties.JksProperties;

@EnableWebSecurity
@Configuration
public class AuthSecurityConfig {

	@Autowired
	private UserRepository userRepository; ;
	
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
	
	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext>jwtEncondingContextOAuth2TokenCustomizer(UserRepository userRepository){
		return 
			(context -> { 
				Authentication authentication = context.getPrincipal();
				if(authentication.getPrincipal() instanceof User) {
					final User user = (User) authentication.getPrincipal();
					final UserEntity userEntity= userRepository.findByEmail(user.getUsername()).orElseThrow();
					
					Set<String>authorities = new HashSet<>();
					for(GrantedAuthority authority : user.getAuthorities()) {
						authorities.add(authority.toString());
					}
					
					context.getClaims().claim("user_id", userEntity.getId().toString());
					context.getClaims().claim("user_fullname", userEntity.getName());
					context.getClaims().claim("authorites", authorities);
					
				
				}
		} );
	}
	
	//Metódo das credenciais dos clients oauth2
	//700c1f1d-c947-4e4d-9791-4a4d625a1daa
	@Bean
	public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) throws Exception{
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
		
		RegisteredClient awuserlogClient = RegisteredClient
				.withId("2")
				.clientId("awblog")
				.clientSecret(passwordEncoder.encode("123456"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("http://localhost:3000/authorized")
				.redirectUri("https://oidcdebugger.com/debug")
				.redirectUri("https://oauth.pstmn.io/v1/callback")
				.scope("myuser:read")
				.scope("myuser:write")
				.scope("posts:write")
				.tokenSettings(
						TokenSettings.builder()
						.accessTokenTimeToLive(Duration.ofMinutes(15))
						.refreshTokenTimeToLive(Duration.ofDays(1))
						.reuseRefreshTokens(false)
						.build())
				.clientSettings(ClientSettings.builder()
						.requireAuthorizationConsent(true)//exibe ou não a tela de consetimento
						.build())
				.build()
				;
		
		return new InMemoryRegisteredClientRepository(
				Arrays.asList(awuserClient,awuserlogClient)
				
				);
	}
	

/*	
    @Bean
    public OAuth2AuthorizationService auth2AuthorizationService(JdbcOperations jdbcOperations,
                                                                RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(
                jdbcOperations,
                registeredClientRepository
        );
    }
/*
    @Bean
    public OAuth2AuthorizationConsentService oAuth2AuthorizationConsentService(JdbcOperations jdbcOperations,
                                                                               RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(
                jdbcOperations,
                registeredClientRepository
        );
    }
	
	*/
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
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	/*@EventListener(ApplicationReadyEvent.class)
	public void saveUseTest() {
		UserEntity u = new UserEntity();
		u.setEmail("luiz.sa.joaquim@gmail.com");
		u.setName("luiz");
		u.setType(Type.ADMIN);
		u.setPassword(passwordEncoder.encode("123456"));
	    userRepository.save(u);
	}*/
	
}
