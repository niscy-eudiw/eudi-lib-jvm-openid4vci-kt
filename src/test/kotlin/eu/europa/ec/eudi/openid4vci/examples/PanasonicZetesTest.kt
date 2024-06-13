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
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.openqa.selenium.By
import java.net.URI
import java.time.Clock
import java.time.Duration
import kotlin.test.assertContains
import kotlin.test.assertEquals

private val PanasonicZetesIssuerId =
    CredentialIssuerId("https://mdlpilot.japaneast.cloudapp.azure.com:8017").getOrThrow()

private object PanasonicZetes :
    HasIssuerId,
    HasTestUser<NoUser> by HasTestUser.HasNoTestUser,
    CanBeUsedWithVciLib,
    CanAuthorizeIssuance<NoUser>,
    CanRequestForCredentialOffer<NoUser> {

    override val issuerId = PanasonicZetesIssuerId
    val LightProfileCfgId = CredentialConfigurationIdentifier("org.iso.18013.5.1.mDL")

    override val cfg: OpenId4VCIConfig = OpenId4VCIConfig(
        clientId = "client-id",
        authFlowRedirectionURI = URI.create("https://oauthdebugger.com/debug"),
        keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
        credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
        dPoPSigner = CryptoGenerator.ecProofSigner(),
        authorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
        parUsage = ParUsage.Never,
        clock = Clock.systemDefaultZone(),
    )

    override suspend fun loginUserAndGetAuthCode(
        authorizationRequestPrepared: AuthorizationRequestPrepared,
        user: NoUser,
        enableHttpLogging: Boolean,
    ): Pair<String, String> {
        fun codeAndStateFromUrl(url: String): Pair<String, String> {
            val r = URLBuilder(url).build()
            return r.parameters["code"].toString() to r.parameters["state"].toString()
        }
        val url = authorizationRequestPrepared.authorizationCodeURL.toString()
        val redirect = ResourceWrapper.chromeDriver().use { wrapper ->
            val driver = wrapper.resource
            driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(5))
            driver.get(url)
            val authorizeButton = driver.findElement(By.id("authorize"))
            authorizeButton.click()
            driver.currentUrl
        }
        return codeAndStateFromUrl(redirect)
    }
    override suspend fun HttpClient.authorizeIssuance(
        loginResponse: HttpResponse,
        user: NoUser,
    ): HttpResponse = loginResponse

    override suspend fun requestCredentialOffer(httpClient: HttpClient, form: CredentialOfferForm<NoUser>): URI {
        return ResourceWrapper.chromeDriver().use { wrapper ->
            val driver = wrapper.resource
            driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(5))
            driver.get(issuerId.toString())
            val showDocumentButton = driver.findElement(By.xpath("/html/body/div[1]/div/div[2]/table/tbody/tr/td[4]/button"))
            showDocumentButton.click()
            val showProfileLightButton = driver.findElement(By.xpath("/html/body/div[2]/div[2]/div/button"))
            showProfileLightButton.click()
            val link = driver.findElement(By.xpath("/html/body/div[2]/a"))
            URI.create(link.getAttribute("href"))
        }
    }
}

@DisplayName("Using Panasonic-Zetas Issuer, VCI Lib should be able to")
class PanasonicZetesTest {

    @Test
    fun `Resolve issuer's metadata`() = runBlocking {
        val (issuerMeta, authServersMeta) = PanasonicZetes.testMetaDataResolution(false)
        assertEquals(1, authServersMeta.size)
        assertContains(issuerMeta.credentialConfigurationsSupported.keys, PanasonicZetes.LightProfileCfgId)
    }

    @Test
    fun `Issue mso_mdoc credential using light profile`() = runBlocking {
        PanasonicZetes.testIssuanceWithAuthorizationCodeFlow(PanasonicZetes.LightProfileCfgId, enableHttLogging = true)
    }
}
