package br.com.ofsajoaquim.authuser.security;

import static org.springframework.security.config.Customizer.withDefaults;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class UserSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            UserDetailsService userDetailsService) throws Exception {
         http.userDetailsService(userDetailsService)
                .csrf().disable()
                .authorizeRequests().anyRequest().authenticated()
                .and()
                	.csrf().disable()
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(jwtAuthenticationConverter());
          
                return http.build();
    }
    
    private JwtAuthenticationConverter jwtAuthenticationConverter() {
    	JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    
    	converter.setJwtGrantedAuthoritiesConverter(
    			jwt -> {
    				List<String> userAuthorities = jwt.getClaimAsStringList("authorites");
    			
    				if(userAuthorities == null)
    					userAuthorities = Collections.emptyList();
    			
    				JwtGrantedAuthoritiesConverter scopesConverter = new JwtGrantedAuthoritiesConverter();
    				Collection<GrantedAuthority> scopeAutorities=  scopesConverter.convert(jwt);
    			
    				scopeAutorities.addAll(userAuthorities.stream()
    						.map(SimpleGrantedAuthority::new)
    						.toList());
    						
    				return scopeAutorities;		
    					
    			}
    			
    	);
    	
    	return converter;
    
    }

}