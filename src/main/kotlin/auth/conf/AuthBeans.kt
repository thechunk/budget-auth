package auth.conf

import org.springframework.context.annotation.Bean
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder

class AuthBeans {
    @Bean
    fun passwordEncoder() : PasswordEncoder = BCryptPasswordEncoder()
}