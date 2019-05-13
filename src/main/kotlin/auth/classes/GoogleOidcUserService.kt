package auth.classes

import auth.repositories.UserRepository
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Service
import common.constants.Auth

@Service
class GoogleOidcUserService(private val repository: UserRepository) : OidcUserService() {
    override fun loadUser(userRequest: OidcUserRequest?): OidcUser {
        val oidcUser = super.loadUser(userRequest)

        val authorities = hashSetOf(
            GrantedAuthority { "read" },
            GrantedAuthority { "write" },
            GrantedAuthority { Auth.AUTHORITIES_GOOGLE_SHEETS_WRITE }
        )
        authorities.addAll(oidcUser.authorities)
        return DefaultOidcUser(authorities, oidcUser.idToken, oidcUser.userInfo)
    }
}