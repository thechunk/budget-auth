package auth.conf

import org.springframework.context.annotation.*
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
        clients
            .inMemory()
            .withClient(environment.getProperty("rcheung.oauth2.client.id"))
            .secret(encoder.encode(environment.getProperty("rcheung.oauth2.client.secret")))
            .authorizedGrantTypes("password", "authorization_code", "refresh_token")
            .scopes("read", "write")
            .redirectUris(environment.getProperty("rcheung.oauth2.client.redirect-uris"))
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