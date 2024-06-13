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
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.DisplayName
import java.net.URI
import java.time.Clock
import kotlin.test.Ignore
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

    // TODO MATR requires specific client_id
    //  Test fail due to tha absence of a known client_id

    override val cfg = OpenId4VCIConfig(
        clientId = "eudiw", // We need to get it from MATR
        authFlowRedirectionURI = URI.create("https://oauthdebugger.com/debug"), // needs to be replaced with our wallet's redirect_uri
        keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
        credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
        dPoPSigner = CryptoGenerator.ecProofSigner(),
        authorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
        clock = Clock.systemDefaultZone(),
    )
    val LightProfileCredCfgId = CredentialConfigurationIdentifier("b59d6a4c-b331-476b-9a4e-ea234c7882c8")

    override suspend fun HttpClient.authorizeIssuance(loginResponse: HttpResponse, user: NoUser): HttpResponse {
        TODO("Not yet implemented")
    }
}

@DisplayName("Using MATR Issuer, VCI Lib should be able to")
class MatrTest {

    @Test
    fun `Resolve issuer's metadata`() = runTest {
        val (issuerMeta, authServersMeta) = Matr.testMetaDataResolution(enableHttLogging = true)
        assertEquals(1, authServersMeta.size)
        assertContains(issuerMeta.credentialConfigurationsSupported.keys, Matr.LightProfileCredCfgId)
    }

    @Test @Ignore
    fun `Issue mso_mdoc credential using light profile`() = runBlocking {
        Matr.testIssuanceWithAuthorizationCodeFlow(Matr.LightProfileCredCfgId, enableHttLogging = true)
    }
}
