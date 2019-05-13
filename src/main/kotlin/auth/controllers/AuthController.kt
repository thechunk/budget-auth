package auth.controllers

import common.entities.UserInfo
import common.entities.UserTokens
import org.springframework.core.env.Environment
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.util.MultiValueMap
import org.springframework.web.bind.annotation.*
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.RestTemplate
import auth.repositories.UserRepository
import common.entities.ClientTokens

@RestController
class AuthController(val environment: Environment, val authorizedClientService: OAuth2AuthorizedClientService) {
    @RequestMapping("/me")
    fun user(principal: OAuth2Authentication) : UserInfo {
        var userInfo = UserInfo(sub = principal.name, name = principal.name)
        val authToken = principal.userAuthentication
        if (authToken is OAuth2AuthenticationToken) {
            val clientToken = authorizedClientService.loadAuthorizedClient<OAuth2AuthorizedClient>(
                authToken.authorizedClientRegistrationId, authToken.name
            )
            val tokens = UserTokens(google = ClientTokens(
                accessToken = clientToken.accessToken.tokenValue,
                expiresAt = clientToken.accessToken.expiresAt,
                refreshToken = clientToken.refreshToken?.tokenValue ?: ""
            ))
            userInfo = UserInfo(sub = principal.name, name = principal.name, tokens = tokens)
        }

        return userInfo
    }

    @RequestMapping("/oauth/token_proxy",
        consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE],
        produces = [MediaType.APPLICATION_JSON_UTF8_VALUE],
        method = [RequestMethod.POST]
    )
    fun tokenProxy(@RequestBody body: MultiValueMap<String, String>): String {
        val clientId = environment.getProperty("rcheung.oauth2.client.id") ?: ""
        val secret = environment.getProperty("rcheung.oauth2.client.secret") ?: ""
        val tokenUrl = environment.getProperty("security.oauth2.client.access-token-uri") ?: ""

        val headers = HttpHeaders()
        headers.setBasicAuth(clientId, secret)
        headers.contentType = MediaType.APPLICATION_FORM_URLENCODED
        val grantType = body["grant_type"]?.first()
        val code = body["code"]?.first()
        val redirectUri = body["redirect_uri"]?.first()
        val entity = HttpEntity("grant_type=$grantType&code=$code&redirect_uri=$redirectUri", headers)

        val restTpl = RestTemplate()
        return try {
            val result = restTpl.exchange(
                tokenUrl,
                HttpMethod.POST,
                entity,
                String::class.java
            )
            result.body ?: ""
        } catch (e: HttpClientErrorException) {
            e.responseBodyAsString
        }
    }
}
