package auth.conf

import auth.classes.GoogleOidcUserService
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
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService

@Configuration
@Import(AuthBeans::class)
@Order(4)
class WebSecurityConfig(val encoder : PasswordEncoder,
                        val userDetailsService: UserDetailsService,
                        val googleOidcUserService: GoogleOidcUserService
) : WebSecurityConfigurerAdapter() {
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
}