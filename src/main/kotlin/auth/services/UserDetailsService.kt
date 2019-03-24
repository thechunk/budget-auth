package auth.services

import auth.classes.UserPrincipal
import auth.repositories.UserRepository
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class UserDetailsService(private val repository: UserRepository) : UserDetailsService {
    override fun loadUserByUsername(username: String): UserDetails {
        try {
            val user = repository.findByUsername(username)
            return UserPrincipal(user)
        } catch(e: EmptyResultDataAccessException) {
            throw UsernameNotFoundException(username)
        }
    }
}