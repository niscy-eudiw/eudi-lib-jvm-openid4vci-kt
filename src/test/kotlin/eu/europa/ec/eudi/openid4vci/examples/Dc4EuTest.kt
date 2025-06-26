/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.openid4vci.examples

import arrow.fx.coroutines.use
import com.nimbusds.jose.jwk.Curve
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.test.runTest
import org.openqa.selenium.By
import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.support.ui.Select
import java.net.URI
import kotlin.test.Test
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

private const val BASE_URL = "https://demo-issuer.wwwallet.org"
private val IssuerId = CredentialIssuerId(BASE_URL).getOrThrow()

internal data class Dc4EuUser(val username: String, val password: String)

internal object Dc4EuIssuer :
    HasIssuerId,
    HasTestUser<Dc4EuUser>,
    CanAuthorizeIssuance<Dc4EuUser>,
    CanBeUsedWithVciLib,
    CanRequestForCredentialOffer<Dc4EuUser> by CanRequestForCredentialOffer.onlyStatelessAuthorizationCode(IssuerId) {

    override val issuerId = IssuerId
    override val testUser = Dc4EuUser("john", password = "secret")
    override val cfg = OpenId4VCIConfig(
        client = Client.Public("wallet-dev"),
        authFlowRedirectionURI = URI.create("https://oauthdebugger.com/debug"),
        keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
        credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
        authorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
        parUsage = ParUsage.IfSupported,
        dPoPSigner = CryptoGenerator.ecProofSigner(),
        issuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned,
    )

    val EHIC = CredentialConfigurationIdentifier("urn:eudi:ehic:1")

    private val threeSeconds = 3.seconds

    override suspend fun loginUserAndGetAuthCode(
        authorizationRequestPrepared: AuthorizationRequestPrepared,
        user: Dc4EuUser,
        enableHttpLogging: Boolean,
    ): Pair<String, String> {
        fun codeAndStateFromUrl(url: String): Pair<String, String> {
            check(url.startsWith(cfg.authFlowRedirectionURI.toString())) { "Invalid redirect_uri $url" }
            val r = URLBuilder(url).build()
            val code = checkNotNull(r.parameters["code"]) { "Missing code" }
            val state = checkNotNull(r.parameters["state"]) { "Missing state" }
            return code to state
        }
        fun setup() = ChromeDriver().apply {
            with(manage().timeouts()) {
                implicitlyWait(threeSeconds.toJavaDuration())
                scriptTimeout(threeSeconds.toJavaDuration())
                pageLoadTimeout(threeSeconds.toJavaDuration())
            }
        }
        return coroutineScope {
            val redirected = async {
                chromeDriver(::setup).use { driver ->
                    // Visit the authorization page (front-channel)
                    driver.get(authorizationRequestPrepared.authorizationCodeURL.toString())

                    // Choose the authentication method SSO
                    Select(driver.findElement(By.id("authMethodDropdown"))).selectByValue("SSO")
                    driver.findElement(By.id("mainBtn")).click()

                    // Visit the login page
                    driver.findElement(By.id("username")).sendKeys(user.username)
                    driver.findElement(By.id("password")).sendKeys(user.password)
                    driver.findElement(By.id("login")).click()

                    // Visit the consent page
                    driver.findElement(By.ByCssSelector("a.credential")).click()
                    driver.findElement(By.ById("DiplomaSelection")).submit()

                    // Grab the redirect uri
                    driver.currentUrl
                }
            }
            codeAndStateFromUrl(redirected.await())
        }
    }

    override suspend fun HttpClient.authorizeIssuance(loginResponse: HttpResponse, user: Dc4EuUser): HttpResponse {
        return loginResponse
    }
}

class Dc4EuTest {

    @Test
    fun `issue EHIC`() = runTest {
        Dc4EuIssuer.testIssuanceWithAuthorizationCodeFlow(
            credCfgId = Dc4EuIssuer.EHIC,
            enableHttpLogging = true,
            batchOption = BatchOption.Specific(2),
        )
    }
}
