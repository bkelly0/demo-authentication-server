package com.bkelly.demo.authentication_server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import javax.sql.DataSource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class AuthConfig {

  private final CorsProperties corsProperties;
  private final CertificateProperties certificateProperties;

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
        new OAuth2AuthorizationServerConfigurer();

    http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
        .with(
            authorizationServerConfigurer,
            authorizationServer ->
                authorizationServer
                    .oidc(Customizer.withDefaults())
                    .authorizationEndpoint(
                        authorizationEndpoint ->
                            authorizationEndpoint.consentPage(
                                "/oauth2/consent"))); // Enable OpenID Connect 1.0

    http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .exceptionHandling(
            exceptions ->
                exceptions.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    request -> "/oauth2/authorize".equals(request.getServletPath())))
        .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));

    return http.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(
            authorize ->
                authorize
                    .requestMatchers(
                        "/",
                        "/login",
                        "/error",
                        "/error/**",
                        "/auth/**",
                        "/.well-known/appspecific/**")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .formLogin(formLogin -> formLogin.loginPage("/login"));

    return http.build();
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(corsProperties.getAllowedOrigins());
    config.setAllowedMethods(corsProperties.getAllowedMethods());
    config.setAllowedHeaders(corsProperties.getAllowedHeaders());
    config.setAllowCredentials(corsProperties.getAllowCredentials());
    config.setMaxAge(corsProperties.getMaxAge());

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
  }

  @Bean("jwkSource")
  @Profile("!generate-jwk")
  public JWKSource<SecurityContext> jwkSourceFromFile() throws Exception {
    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    try (FileInputStream fis = new FileInputStream(certificateProperties.getFile())) {
      keyStore.load(fis, certificateProperties.getPassword().toCharArray());
    }

    String alias = keyStore.aliases().nextElement();
    RSAPrivateKey privateKey =
        (RSAPrivateKey) keyStore.getKey(alias, certificateProperties.getPassword().toCharArray());
    RSAPublicKey publicKey =
        (RSAPublicKey)
            ((java.security.cert.X509Certificate) keyStore.getCertificate(alias)).getPublicKey();

    RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(alias).build();

    JWKSet jwkSet = new JWKSet(rsaKey);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
  }

  @Profile("generate-jwk")
  @Bean("jwkSource")
  public JWKSource<SecurityContext> jwkSourceGenerated() {
    log.warn("Using generated JWKSource");
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAKey rsaKey =
        new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
  }

  private static KeyPair generateRsaKey() {
    KeyPair keyPair;
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      keyPair = keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
    return keyPair;
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings(
      @Value("${app.issuer}") String issuer) {
    // explicitly set issuer to avoid http/https mismatch issues when running behind a reverse proxy
    return AuthorizationServerSettings.builder().issuer(issuer).build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  @Bean
  @Profile("database")
  public UserDetailsManager userDetailsManager(DataSource dataSource) {
    return new JdbcUserDetailsManager(dataSource);
  }

  @Bean
  @Profile("!database")
  public UserDetailsManager inMemoryUserDetailsManager() {
    log.warn(
        "Not using database profile; using in-memory UserDetailsManager. Users will not persist across restarts.");
    return new InMemoryUserDetailsManager();
  }

  @Bean
  @Profile("database")
  public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
    return new JdbcRegisteredClientRepository(jdbcTemplate);
  }

  @Bean
  @Profile("!database")
  public RegisteredClientRepository inMemoryRegisteredClientRepository() {
    log.warn(
        "Not using database profile; using in-memory RegisteredClientRepository. Registered clients will not persist across restarts.");
    RegisteredClient pkceClient =
        RegisteredClient.withId("fallback-pkce-client")
            .clientId("fallback-pkce-client")
            .clientName("Fallback PKCE Client")
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("http://127.0.0.1:8081/callback")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .clientSettings(ClientSettings.builder().requireProofKey(true).build())
            .build();
    return new InMemoryRegisteredClientRepository(pkceClient);
  }

  @Bean
  @Profile("database")
  public OAuth2AuthorizationService oAuth2AuthorizationService(
      JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
    return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
  }

  @Bean
  @Profile("!database")
  public OAuth2AuthorizationService inMemoryOAuth2AuthorizationService() {
    log.warn(
        "Not using database profile; using in-memory OAuth2AuthorizationService. Authorizations will not persist across restarts.");
    return new InMemoryOAuth2AuthorizationService();
  }

  @Bean
  @Profile("database")
  public OAuth2AuthorizationConsentService oAuth2AuthorizationConsentService(
      JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
    return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
  }

  @Bean
  @Profile("!database")
  public OAuth2AuthorizationConsentService inMemoryOAuth2AuthorizationConsentService() {
    log.warn(
        "Not using database profile; using in-memory OAuth2AuthorizationConsentService. Consents will not persist across restarts.");
    return new InMemoryOAuth2AuthorizationConsentService();
  }
}
