package com.bkelly.demo.authentication_server.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "app.certificate")
@Data
public class CertificateProperties {
  private String file;
  private String password;
}
