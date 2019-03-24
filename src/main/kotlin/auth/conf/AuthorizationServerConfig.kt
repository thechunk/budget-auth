package auth.conf

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.core.env.Environment
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore

@Configuration
@EnableAuthorizationServer
@Import(AuthBeans::class)
class AuthorizationServerConfig(val encoder : PasswordEncoder, val authenticationManager: AuthenticationManager,
                                val userDetailsService: UserDetailsService, val environment: Environment
) : AuthorizationServerConfigurerAdapter() {
    override fun configure(security: AuthorizationServerSecurityConfigurer) {
        security
            .passwordEncoder(encoder)
            .tokenKeyAccess("permitAll()")
            .checkTokenAccess("isAuthenticated()")
            .allowFormAuthenticationForClients()
    }

    override fun configure(clients: ClientDetailsServiceConfigurer) {
        val clientId = environment.getProperty("rcheung.oauth2.client.id") ?: ""
        val secret = environment.getProperty("rcheung.oauth2.client.secret") ?: ""
        val redirectUris = environment.getProperty("rcheung.oauth2.client.redirect-uris") ?: ""
        clients
            .inMemory()
            .withClient(clientId)
            .secret(encoder.encode(secret))
            .authorizedGrantTypes("password", "authorization_code", "refresh_token")
            .scopes("read", "user_info")
            .redirectUris(redirectUris)
    }

    override fun configure(endpoints: AuthorizationServerEndpointsConfigurer) {
        endpoints
            .tokenStore(tokenStoreBean())
            .userDetailsService(userDetailsService)
            .authenticationManager(authenticationManager)
    }

    @Bean
    fun tokenStoreBean(): TokenStore = InMemoryTokenStore()
}