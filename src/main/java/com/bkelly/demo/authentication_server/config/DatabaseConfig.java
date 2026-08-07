package com.bkelly.demo.authentication_server.config;

import javax.sql.DataSource;
import org.springframework.boot.jdbc.autoconfigure.DataSourceProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("database")
public class DatabaseConfig {

  @Bean
  public DataSource dataSource(DataSourceProperties properties) {
    return properties.initializeDataSourceBuilder().build();
  }
}
