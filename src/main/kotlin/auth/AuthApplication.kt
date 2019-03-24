package auth

import auth.entities.User
import auth.repositories.UserRepository
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.boot.CommandLineRunner
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.ComponentScan
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer

@EnableAutoConfiguration
@ComponentScan
@EnableResourceServer
class AuthApplication {
    private val logger: Logger = LoggerFactory.getLogger(AuthApplication::class.java)

    @Bean
    fun demo(repository: UserRepository, encoder: PasswordEncoder) = CommandLineRunner {
        repository.save(User(
            username = "user",
            password = encoder.encode("password")
        ))
        repository.findAll().forEach { logger.debug(it.username) }
    }
}

fun main(args: Array<String>) {
    runApplication<AuthApplication>(*args)
}

