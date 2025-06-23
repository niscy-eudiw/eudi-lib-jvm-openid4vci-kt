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
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.DisplayName
import java.net.URI
import java.time.Clock
import kotlin.test.Test

private val IssuerId = CredentialIssuerId("https://issuer-openid4vc.ssi.tir.budru.de/openid-gain").getOrThrow()

private object Bdr :
    HasIssuerId,
    CanRequestForCredentialOffer<NoUser> by CanRequestForCredentialOffer.onlyStatelessAuthorizationCode(IssuerId),
    HasTestUser<NoUser> by HasTestUser.HasNoTestUser,
    CanAuthorizeIssuance<NoUser>,
    CanBeUsedWithVciLib {

    override val issuerId = IssuerId

    /**
     * mDL in mso_mdoc
     */
    val LspPotentialInteropT1Light = CredentialConfigurationIdentifier("LspPotentialInteropT1Light")

    /**
     * PID in sd-jwt-vc
     */
    val LspPotentialInteropT2Light = CredentialConfigurationIdentifier("LspPotentialInteropT2Light")

    override val cfg: OpenId4VCIConfig = OpenId4VCIConfig(
        clientId = "eudiw", // We can use whatever we like
        authFlowRedirectionURI = URI.create("https://oauthdebugger.com/debug"), // needs to be replaced with our wallet's redirect_uri
        keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
        credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
        dPoPSigner = CryptoGenerator.ecProofSigner(), // we can set or unset the dPopSigner. Both work
        authorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES, // Needs to explicitly set this to FAVOR_SCOPES
        parUsage = ParUsage.Never, // Needs to explicitly set this to Never
        clock = Clock.systemDefaultZone(),
    )

    override suspend fun loginUserAndGetAuthCode(
        authorizationRequestPrepared: AuthorizationRequestPrepared,
        user: NoUser,
        enableHttpLogging: Boolean,
    ): Pair<String, String> {
        // BTR automatically authorizes every request
        // Then performs an intermediate redirect
        // Then performs the expected redirect
        val response = HttpClient { followRedirects = false }.use { httpClient ->
            val loginResponse = httpClient.visitAuthorizationPage(authorizationRequestPrepared)
            httpClient.authorizeIssuance(loginResponse, user)
        }
        return response.parseCodeAndStatus()
    }

    override suspend fun HttpClient.authorizeIssuance(loginResponse: HttpResponse, user: NoUser): HttpResponse {
        require(loginResponse.status.value == 302)
        val redirectLocation = checkNotNull(loginResponse.headers["Location"])
        return get(redirectLocation)
    }
}

@DisplayName("Using BDR Issuer, VCI Lib should be able to")
class BdrTest {

    @Test
    fun `Resolve issuer metadata`() = runTest {
        Bdr.testMetaDataResolution(enableHttpLogging = false)
    }

    @Test
    fun `Issue mDL in mso_mdoc using light profile, JWT proofs`() = runTest {
        Bdr.testIssuanceWithAuthorizationCodeFlow(
            Bdr.LspPotentialInteropT1Light,
            enableHttpLogging = false,
            batchOption = BatchOption.DontUse,
        )
    }

    @Test
    fun `Issue PID in sd-jwt-vc using light profile, JWT proofs`() = runTest {
        Bdr.testIssuanceWithAuthorizationCodeFlow(
            Bdr.LspPotentialInteropT2Light,
            enableHttpLogging = false,
            batchOption = BatchOption.DontUse,
        )
    }
}
