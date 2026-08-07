package com.bkelly.demo.authentication_server.config;

import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "app.bootstrap")
public class BootstrapProperties {
  private List<DefaultUserProperties> defaultUsers;
  private DefaultClientProperties defaultClient;

  @Data
  static final class DefaultUserProperties {
    String username;
    String password;
    String roles;
  }

  @Data
  static final class DefaultClientProperties {
    String id;
    String secret;
    String name;
    String redirectUri;
    String postLogoutRedirectUri;
    List<String> scopes;
  }
}
