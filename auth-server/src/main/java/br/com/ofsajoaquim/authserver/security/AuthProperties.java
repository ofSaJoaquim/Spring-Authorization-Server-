package br.com.ofsajoaquim.authserver.security;

import javax.validation.constraints.NotBlank;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import lombok.Getter;
import lombok.Setter;

@Component
@Validated
@ConfigurationProperties
@Getter
@Setter
public class AuthProperties {
	
	@NotBlank
	private String providerUri;

	@NotBlank
	private JksProperties jks;
	
	
	@Getter
	@Setter
	static class JksProperties {
		
		@NotBlank
		private String keypass;
		
		@NotBlank
		private String storepass;
		
		@NotBlank
		private String alias;
		
		@NotBlank
		private String path;
	}
	
}
