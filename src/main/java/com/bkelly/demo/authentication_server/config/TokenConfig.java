package com.bkelly.demo.authentication_server.config;

import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
public class TokenConfig {
  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
    return context -> {
      // Only modify claims for Access Tokens (ignore refresh tokens, etc.)
      if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
        Authentication principal = context.getPrincipal();

        // Extract authorities from the authenticated user
        Set<String> authorities =
            principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(Objects::nonNull)
                .map(role -> role.replaceFirst("ROLE_", ""))
                .collect(Collectors.toSet());

        // Add the collection to a custom "roles" claim in the JWT
        context.getClaims().claim("roles", authorities);
      }
    };
  }
}
