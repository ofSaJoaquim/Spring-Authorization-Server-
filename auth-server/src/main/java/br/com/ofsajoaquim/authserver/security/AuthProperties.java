package br.com.ofsajoaquim.authserver.security;

import javax.validation.constraints.NotBlank;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import lombok.Getter;
import lombok.Setter;

@Component
@Validated
@Configuration
@Getter
@Setter
public class AuthProperties {
	
	
	@NotBlank
	@Value("${aw.auth.provider-uri}")
	private String providerUri = "http://localhost:8082";

	@NotBlank
	private JksProperties jks = new JksProperties();
	
	
	@Getter
	@Setter
	@Configuration
	@Component
	static class JksProperties {
		
		@NotBlank
		@Value("${aw.auth.jks.keypass}")
		private String keypass = "123456";
		
		@NotBlank
		@Value("${aw.auth.jks.storepass}")
		private String storepass = "123456";
		
		@NotBlank
		@Value("${aw.auth.jks.alias}")
		private String alias ="awserver";
		
		@NotBlank
		@Value("${aw.auth.jks.path}")
		private String path = "keystore/awserver.jks";
	}
	
}
