package auth.controllers

import com.fasterxml.jackson.annotation.JsonCreator
import org.springframework.core.env.Environment
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.security.Principal
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.RestTemplate

@RestController
class AuthController(val environment: Environment) {
    @RequestMapping("/user/me")
    fun user(principal: Principal) : Principal {
        return principal
    }

    @RequestMapping("/oauth/token_proxy",
        produces = [MediaType.APPLICATION_JSON_UTF8_VALUE],
        method = [RequestMethod.POST]
    )
    fun tokenProxy(@RequestBody body: TokenProxyRequestBody): String {
        val clientId = environment.getProperty("rcheung.oauth2.client.id") ?: ""
        val secret = environment.getProperty("rcheung.oauth2.client.secret") ?: ""
        val tokenUrl = environment.getProperty("security.oauth2.client.access-token-uri") ?: ""

        val headers = HttpHeaders()
        headers.setBasicAuth(clientId, secret)
        headers.contentType = MediaType.APPLICATION_FORM_URLENCODED
        val code = body.code
        val entity = HttpEntity("grant_type=authorization_code&code=$code", headers)

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

    data class TokenProxyRequestBody @JsonCreator constructor(
        val code: String
    )
}
