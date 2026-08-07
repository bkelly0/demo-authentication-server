package com.bkelly.demo.authentication_server.config;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.util.StringUtils;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class DefaultCredentialsSeederConfig {
  private final BootstrapProperties bootstrapProperties;

  @Bean
  public CommandLineRunner defaultPrincipalSeeder(
      UserDetailsManager userDetailsManager,
      RegisteredClientRepository registeredClientRepository,
      PasswordEncoder passwordEncoder) {
    return args -> {
      List<BootstrapProperties.DefaultUserProperties> defaultUsers =
          bootstrapProperties.getDefaultUsers();
      if (defaultUsers != null) {
        for (BootstrapProperties.DefaultUserProperties userProperties : defaultUsers) {
          String defaultUsername = userProperties.getUsername();
          String defaultUserPassword = userProperties.getPassword();
          String defaultUserRoles = userProperties.getRoles();

          if (!StringUtils.hasText(defaultUsername)) {
            log.warn(
                "Skipping startup user creation: configured default user is missing a username.");
            continue;
          }

          if (!StringUtils.hasText(defaultUserPassword)) {
            continue;
          }

          String[] roles = parseRoles(defaultUserRoles);
          UserDetails defaultUser =
              User.withUsername(defaultUsername)
                  .password(passwordEncoder.encode(defaultUserPassword))
                  .roles(roles.length == 0 ? new String[] {"DEFAULT"} : roles)
                  .build();

          if (userDetailsManager.userExists(defaultUsername)) {
            userDetailsManager.updateUser(defaultUser);
            log.info(
                "Updated default user '{}' from startup configuration with roles {}.",
                defaultUsername,
                defaultUserRoles);
          } else {
            userDetailsManager.createUser(defaultUser);
            log.info(
                "Created default user '{}' from startup configuration with roles {}.",
                defaultUsername,
                defaultUserRoles);
          }
        }
      }

      BootstrapProperties.DefaultClientProperties defaultClientProperties =
          bootstrapProperties.getDefaultClient();
      if (defaultClientProperties == null) {
        return;
      }

      String defaultClientId = defaultClientProperties.getId();
      String defaultClientSecret = defaultClientProperties.getSecret();
      String defaultClientName = defaultClientProperties.getName();
      String defaultClientRedirectUri = defaultClientProperties.getRedirectUri();
      List<String> defaultClientScopes = defaultClientProperties.getScopes();
      String postLogoutRedirectUri = defaultClientProperties.getPostLogoutRedirectUri();

      if (!StringUtils.hasText(defaultClientSecret)) {
        return;
      }

      if (!StringUtils.hasText(defaultClientId)
          || !StringUtils.hasText(defaultClientName)
          || !StringUtils.hasText(defaultClientRedirectUri)) {
        log.warn(
            "Skipping startup client creation: default client is missing required fields (id, name, or redirect-uri).");
        return;
      }

      if (registeredClientRepository.findByClientId(defaultClientId) != null) {
        log.info("Default client '{}' already exists; skipping startup creation.", defaultClientId);
        return;
      }

      RegisteredClient.Builder defaultClientBuilder =
          RegisteredClient.withId(UUID.randomUUID().toString())
              .clientId(defaultClientId)
              .clientName(defaultClientName)
              .clientSecret(passwordEncoder.encode(defaultClientSecret))
              .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
              .redirectUri(defaultClientRedirectUri)
              .postLogoutRedirectUri(postLogoutRedirectUri)
              .clientSettings(
                  ClientSettings.builder()
                      .requireProofKey(true)
                      .requireAuthorizationConsent(false)
                      .build());

      for (String scope : defaultClientScopes == null ? List.<String>of() : defaultClientScopes) {
        if (!StringUtils.hasText(scope)) {
          continue;
        }
        defaultClientBuilder.scope(scope);
      }

      registeredClientRepository.save(defaultClientBuilder.build());
      log.info(
          "Created default client '{}' with scopes {} from startup configuration.",
          defaultClientId,
          defaultClientScopes);
    };
  }

  private static String[] parseRoles(String commaSeparatedRoles) {
    return Arrays.stream(parseCsv(commaSeparatedRoles))
        .map(role -> role.startsWith("ROLE_") ? role.substring("ROLE_".length()) : role)
        .toArray(String[]::new);
  }

  private static String[] parseCsv(String csv) {
    if (!StringUtils.hasText(csv)) {
      return new String[0];
    }

    return Arrays.stream(csv.split(","))
        .map(String::trim)
        .filter(StringUtils::hasText)
        .toArray(String[]::new);
  }
}
