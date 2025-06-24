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
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import org.openqa.selenium.By
import org.openqa.selenium.support.ui.Select
import java.net.URI
import java.time.Duration
import kotlin.test.Test
import kotlin.time.Duration.Companion.seconds

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
    val DIPLOMA = CredentialConfigurationIdentifier("urn:credential:diploma")

    override suspend fun loginUserAndGetAuthCode(
        authorizationRequestPrepared: AuthorizationRequestPrepared,
        user: Dc4EuUser,
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
                chromeDriver().use { driver ->
                    val threeSeconds = Duration.ofSeconds(3)
                    val authorizeUrl = authorizationRequestPrepared.authorizationCodeURL.toString()

                    driver.manage().timeouts().implicitlyWait(threeSeconds)
                    driver.manage().timeouts().scriptTimeout(threeSeconds)
                    driver.manage().timeouts().pageLoadTimeout(threeSeconds)

                    driver.get(authorizeUrl)
                    val dropDown = driver.findElement(By.id("authMethodDropdown"))
                    Select(dropDown).selectByValue("SSO")

                    val proceedButton = driver.findElement(By.id("mainBtn"))
                    delay(threeSeconds.toMillis())
                    proceedButton.click()
                    delay(threeSeconds.toMillis())

                    driver.findElement(By.id("username")).sendKeys(user.username)
                    driver.findElement(By.id("password")).sendKeys(user.password)
                    delay(threeSeconds.toMillis())
                    driver.findElement(By.id("login")).click()
                    delay(threeSeconds.toMillis())

                    delay(3.seconds)
                    driver.findElement(By.ByCssSelector("a.credential")).click()
                    delay(threeSeconds.toMillis())

                    driver.findElement(By.ById("DiplomaSelection")).submit()

                    delay(threeSeconds.toMillis())
                    val redirectUrl = driver.currentUrl
                    redirectUrl
                }
            }
            codeAndStateFromUrl(redirected.await()).also { (code, status) ->
                println("code $code")
                println("status $status")
            }
        }
    }

    override suspend fun HttpClient.authorizeIssuance(loginResponse: HttpResponse, user: Dc4EuUser): HttpResponse {
        return loginResponse
    }
}

class Dc4EuTest {

    @Test
    fun resolveCredentialIssuerMetadata() = runTest {
        val (credentialIssuerMetadata, authServersMetadata) =
            Dc4EuIssuer.testMetaDataResolution(true)

        for ((id, cfg) in credentialIssuerMetadata.credentialConfigurationsSupported) {
            println("--> Credential configuration id: $id")
            println("    -> Credential configuration display name: ${cfg.display.firstOrNull()?.name}")
            println("    -> Credential configuration scope: ${cfg.scope}")
        }
    }

    @Test
    fun `issue EHIC`() = runTest {
        Dc4EuIssuer.testIssuanceWithAuthorizationCodeFlow(
            credCfgId = Dc4EuIssuer.EHIC,
            enableHttpLogging = true,
            batchOption = BatchOption.Specific(1),
        )
    }
}
