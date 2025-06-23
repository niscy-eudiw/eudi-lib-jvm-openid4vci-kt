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

import com.nimbusds.jose.jwk.Curve
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.DisplayName
import org.openqa.selenium.By
import org.openqa.selenium.WebElement
import java.net.URI
import java.time.Clock
import java.time.Duration
import kotlin.test.Test

private val IssuerId =
    CredentialIssuerId("https://interop-service.rac-shared.staging.identity-dev.idemia.io").getOrThrow()

private object Idemia :
    HasIssuerId,
    HasTestUser<NoUser> by HasTestUser.HasNoTestUser,
    CanBeUsedWithVciLib,
    CanAuthorizeIssuance<NoUser>,
    CanRequestForCredentialOffer<NoUser> {
    override val issuerId = IssuerId
    override val cfg: OpenId4VCIConfig =
        OpenId4VCIConfig(
            clientId = "eudiw", // We can use whatever we like
            authFlowRedirectionURI = URI.create("https://oauthdebugger.com/debug"), // needs to be replaced with our wallet's redirect_uri
            keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
            credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
            dPoPSigner = CryptoGenerator.ecProofSigner(),
            authorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
            clock = Clock.systemDefaultZone(),
        )

    val mDL = CredentialConfigurationIdentifier("org.iso.18013.5.1.mDL")
    val pid = CredentialConfigurationIdentifier("eu.europa.ec.eudi.pid.1")

    override suspend fun requestCredentialOffer(httpClient: HttpClient, form: CredentialOfferForm<NoUser>): URI {
        val uri = ResourceWrapper.chromeDriver().use { wrapper ->
            val driver = wrapper.resource
            driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(3))
            driver.get("https://interop-service.rac-shared.staging.identity-dev.idemia.io/openid4vci.html")
            val credentialOfferLink: WebElement = driver.findElement(By.linkText("Link"))
            val uri = credentialOfferLink.getAttribute("href")
            uri
        }

        return URI.create(uri)
    }

    override suspend fun loginUserAndGetAuthCode(
        authorizationRequestPrepared: AuthorizationRequestPrepared,
        user: NoUser,
        enableHttpLogging: Boolean,
    ): Pair<String, String> {
        fun codeAndStateFromUrl(url: String): Pair<String, String> {
            require(url.startsWith(cfg.authFlowRedirectionURI.toString())) { "Invalid redirect_uri $url" }
            val r = URLBuilder(url).build()
            val code = checkNotNull(r.parameters["code"]) { "Missing code" }
            val state = checkNotNull(r.parameters["state"]) { "Missing state" }
            return code to state
        }
        return coroutineScope {
            val redirected = async {
                ResourceWrapper.chromeDriver().use { wrapper ->
                    val threeSeconds = Duration.ofSeconds(3)
                    val driver = wrapper.resource
                    val authorizeUrl = authorizationRequestPrepared.authorizationCodeURL.toString()

                    driver.manage().timeouts().implicitlyWait(threeSeconds)
                    driver.manage().timeouts().scriptTimeout(threeSeconds)
                    driver.manage().timeouts().pageLoadTimeout(threeSeconds)

                    driver.get(authorizeUrl)
                    val button = driver.findElement(By.id("btn-im"))
                    delay(threeSeconds.toMillis())
                    button.click()
                    delay(threeSeconds.toMillis())

                    driver.currentUrl
                }
            }
            codeAndStateFromUrl(redirected.await())
        }
    }

    override suspend fun HttpClient.authorizeIssuance(loginResponse: HttpResponse, user: NoUser): HttpResponse {
        return loginResponse
    }
}

@DisplayName("Using Idemia Issuer, VCI Lib should be able to")
class IdemiaTest {

    @Test
    fun `Resolve issuer metadata`() = runTest {
        Idemia.testMetaDataResolution(enableHttpLogging = false)
    }

    @Test
    fun `Issue mDL credential using light profile`() = runBlocking {
        Idemia.testIssuanceWithAuthorizationCodeFlow(Idemia.mDL, enableHttpLogging = false)
    }

    @Test
    fun `Issue pid credential using authorization code flow`() = runBlocking {
        Idemia.testIssuanceWithAuthorizationCodeFlow(Idemia.pid, enableHttpLogging = false)
    }
}
