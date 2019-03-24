package auth.conf

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

@Configuration
@Import(AuthBeans::class)
@Order(1)
class WebSecurityConfiguration(val encoder : PasswordEncoder, val userDetailsService: UserDetailsService)
    : WebSecurityConfigurerAdapter() {
    override fun configure(web: WebSecurity) {
        web.ignoring()
            .antMatchers("/h2-console/**")
    }

    override fun configure(http: HttpSecurity) {
          http.authorizeRequests()
                  .antMatchers("/login").permitAll()
              .and()
                  .formLogin()
              .and().csrf().disable()
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