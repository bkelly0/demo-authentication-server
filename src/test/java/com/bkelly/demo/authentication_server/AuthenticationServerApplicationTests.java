package com.bkelly.demo.authentication_server;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(properties = "spring.cloud.compatibility-verifier.enabled=false")
@ActiveProfiles({"in-memory", "generate-jwk"})
class AuthenticationServerApplicationTests {

  @Test
  void contextLoads() {}
}
