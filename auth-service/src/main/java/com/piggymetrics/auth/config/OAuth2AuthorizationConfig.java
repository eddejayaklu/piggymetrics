package com.piggymetrics.auth.config;

import com.piggymetrics.auth.service.security.MongoUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.time.Duration;
import java.util.UUID;

/**
 * OAuth2 Authorization Server Configuration
 */
@Configuration
public class OAuth2AuthorizationConfig {

    @Autowired
    private Environment env;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        http
                .exceptionHandling(exceptions ->
                        exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // Helper to generate a unique client secret based on clientId and the base secret value
        // This ensures that even if the base secret is the same, each client secret is unique.
        String browserSecret = uniqueSecret("browser", env.getProperty("BROWSER_SERVICE_PASSWORD", "default-browser-password"));
        String accountSecret = uniqueSecret("account-service", env.getProperty("ACCOUNT_SERVICE_PASSWORD"));
        String statisticsSecret = uniqueSecret("statistics-service", env.getProperty("STATISTICS_SERVICE_PASSWORD"));
        String notificationSecret = uniqueSecret("notification-service", env.getProperty("NOTIFICATION_SERVICE_PASSWORD"));

        RegisteredClient browserClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("browser")
                // For public clients, no secret is required
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD) // Note: password grant is deprecated
                .scope("ui")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();

        RegisteredClient accountServiceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("account-service")
                .clientSecret(accountSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("server")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();

        RegisteredClient statisticsServiceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("statistics-service")
                .clientSecret(statisticsSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("server")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();

        RegisteredClient notificationServiceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("notification-service")
                .clientSecret(notificationSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("server")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();

        return new InMemoryRegisteredClientRepository(
                browserClient,
                accountServiceClient,
                statisticsServiceClient,
                notificationServiceClient
        );
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .refreshTokenTimeToLive(Duration.ofDays(1))
                .build();
    }

    /**
     * Generate a unique secret by appending the clientId to the base secret.
     * This way, even if the base secret is identical across clients, the resulting secret will be unique.
     */
    private String uniqueSecret(String clientId, String baseSecret) {
        // Ensure baseSecret is not null; if it is, use a default value or generate a random one.
        if (baseSecret == null) {
            baseSecret = UUID.randomUUID().toString();
        }
        return "{noop}" + clientId + "-" + baseSecret;
    }
}
