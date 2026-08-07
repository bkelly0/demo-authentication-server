package com.bkelly.demo.authentication_server;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthPageController {

  private final RegisteredClientRepository registeredClientRepository;

  public AuthPageController(RegisteredClientRepository registeredClientRepository) {
    this.registeredClientRepository = registeredClientRepository;
  }

  @GetMapping("/")
  public String home() {
    return "home";
  }

  @GetMapping("/login")
  public String login(
      @RequestParam(value = "error", required = false) String error,
      @RequestParam(value = "logout", required = false) String logout,
      Model model) {
    model.addAttribute("hasError", error != null);
    model.addAttribute("hasLogout", logout != null);
    return "login";
  }

  @GetMapping("/oauth2/consent")
  public String consent(
      @RequestParam("client_id") String clientId,
      @RequestParam("scope") String scope,
      @RequestParam("state") String state,
      Model model) {
    RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
    String clientName = registeredClient != null ? registeredClient.getClientName() : clientId;
    Set<String> scopes = new LinkedHashSet<>(Arrays.asList(scope.split("\\s+")));
    Map<String, String> scopeDescriptions = new LinkedHashMap<>();
    for (String requestedScope : scopes) {
      scopeDescriptions.put(requestedScope, describeScope(requestedScope));
    }

    model.addAttribute("clientId", clientId);
    model.addAttribute("clientName", clientName);
    model.addAttribute("state", state);
    model.addAttribute("scopes", scopes);
    model.addAttribute("scopeDescriptions", scopeDescriptions);
    return "consent";
  }

  private static String describeScope(String scope) {
    return switch (scope) {
      case "openid" -> "Confirm your identity.";
      case "profile" -> "Read your basic profile details.";
      case "email" -> "Read your email address.";
      case "offline_access" -> "Keep access while you are offline.";
      default -> "Access scope: " + scope;
    };
  }
}
