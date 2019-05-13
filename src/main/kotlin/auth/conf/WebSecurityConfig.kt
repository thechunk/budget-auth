package auth.conf

import auth.classes.GoogleOidcUserService
import auth.conf.WebSecurityConfig.CustomOAuth2ClientRegistrationId.*
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesRegistrationAdapter
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.core.annotation.Order
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import java.util.HashMap

@Configuration
@EnableConfigurationProperties(OAuth2ClientProperties::class)
@Import(AuthBeans::class)
@Order(4)
class WebSecurityConfig(val encoder : PasswordEncoder,
                        val userDetailsService: UserDetailsService,
                        val googleOidcUserService: GoogleOidcUserService,
                        val properties: OAuth2ClientProperties
) : WebSecurityConfigurerAdapter() {
    enum class CustomOAuth2ClientRegistrationId(val registrationId: String) {
        GOOGLE("google")
    }

    override fun configure(web: WebSecurity) {
        web.debug(true)
        web.ignoring()
            .antMatchers("/h2-console/**")
    }

    override fun configure(http: HttpSecurity) {
        http.authorizeRequests()
            .antMatchers("/oauth/token_proxy")
            .permitAll()
            .anyRequest().authenticated()
            .and().formLogin()
            .and().oauth2Login()
            .userInfoEndpoint()
            .userService(DefaultOAuth2UserService())
            .oidcUserService(googleOidcUserService)
          http.csrf().disable()
    }

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.authenticationProvider(authenticationProviderBean())
    }

    @Bean
    fun authenticationProviderBean() : AuthenticationProvider {
        val provider = DaoAuthenticationProvider()
        provider.setPasswordEncoder(encoder)
        provider.setUserDetailsService(userDetailsService)
        return provider
    }

    @Bean
    override fun authenticationManagerBean() : AuthenticationManager = super.authenticationManagerBean()

    @Bean
    fun clientRegistrationRepository() : ClientRegistrationRepository {
        val registrations = getClientRegistrations(this.properties).values.toList()
        return InMemoryClientRegistrationRepository(registrations)
    }

    private fun getClientRegistrations(
        properties: OAuth2ClientProperties
    ): Map<String, ClientRegistration> {
        val registrations = OAuth2ClientPropertiesRegistrationAdapter.getClientRegistrations(properties)
        val clientRegistrations = HashMap<String, ClientRegistration>()
        properties.registration
            .filterNot { p ->
                CustomOAuth2ClientRegistrationId.values().any { it.registrationId == p.value.clientId }
            }
            .forEach { key, value ->
                clientRegistrations[key] = getCustomClientRegistration(key, value) ?: throw IllegalArgumentException()
            }
        registrations.putAll(clientRegistrations)
        return registrations
    }

    private fun getCustomClientRegistration(registrationId: String,
                                            properties: OAuth2ClientProperties.Registration) : ClientRegistration? {
        var builder: ClientRegistration.Builder? = null
        if (registrationId == GOOGLE.registrationId) {
            builder = CommonOAuth2Provider.GOOGLE.getBuilder(registrationId)
            builder.authorizationUri("https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&prompt=consent")
        }
        builder
            ?.clientId(properties.clientId)
            ?.clientSecret(properties.clientSecret)
        return builder?.build()
    }
}