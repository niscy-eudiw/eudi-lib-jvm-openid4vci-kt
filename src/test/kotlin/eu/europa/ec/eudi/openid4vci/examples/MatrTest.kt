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
import java.net.URI
import java.time.Clock
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals

private val IssuerId = CredentialIssuerId("https://launchpad.vii.proton.mattrlabs.io").getOrThrow()

private object Matr :
    HasIssuerId,
    CanBeUsedWithVciLib,
    CanAuthorizeIssuance<NoUser>,
    HasTestUser<NoUser> by HasTestUser.HasNoTestUser,
    CanRequestForCredentialOffer<NoUser> by CanRequestForCredentialOffer.onlyStatelessAuthorizationCode(IssuerId) {

    override val issuerId = IssuerId

    override val cfg = OpenId4VCIConfig(
        clientId = "wallet-dev", // We need to get it from MATR
        authFlowRedirectionURI = URI.create("https://oauthdebugger.com/debug"), // needs to be replaced with our wallet's redirect_uri
        keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
        credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
        dPoPSigner = CryptoGenerator.ecProofSigner(),
        authorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
        parUsage = ParUsage.Never,
        clock = Clock.systemDefaultZone(),
    )
    val LightProfileCredCfgId = CredentialConfigurationIdentifier("b59d6a4c-b331-476b-9a4e-ea234c7882c8")
    val pid = CredentialConfigurationIdentifier("6536bd24-9eae-4f31-aa8b-1386ae547b46")
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
                    delay(threeSeconds.toMillis())
                    val button = driver.findElement(By.xpath("  /html/body/main/div/div/div/form/div/button"))
                    // delay(threeSeconds.toMillis())
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

@DisplayName("Using MATR Issuer, VCI Lib should be able to")
class MatrTest {

    @Test
    fun `Resolve issuer's metadata`() = runTest {
        val (issuerMeta, authServersMeta) = Matr.testMetaDataResolution(enableHttpLogging = true)
        assertEquals(1, authServersMeta.size)
        assertContains(issuerMeta.credentialConfigurationsSupported.keys, Matr.LightProfileCredCfgId)
    }

    @Test
    fun `Issue mDL credential using light profile with JWT proof`() = runBlocking {
        Matr.testIssuanceWithAuthorizationCodeFlow(
            Matr.LightProfileCredCfgId,
            enableHttpLogging = false,
            batchOption = BatchOption.DontUse,
        )
    }

    @Test
    fun `Issue pid in mso_mdoc using auth code flow with JWT proof`() = runBlocking {
        Matr.testIssuanceWithAuthorizationCodeFlow(
            Matr.pid,
            enableHttpLogging = false,
            batchOption = BatchOption.DontUse,
        )
    }
}
