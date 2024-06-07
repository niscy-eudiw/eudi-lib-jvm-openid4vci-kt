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
import eu.europa.ec.eudi.openid4vci.internal.DefaultCredentialOfferRequestResolver
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import org.jsoup.Jsoup
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.assertDoesNotThrow
import java.net.URI
import java.time.Clock
import kotlin.test.*

private object Authlete :
    HasIssuerId,
    CanBeUsedWithVciLib,
    CanAuthorizeIssuance<Authlete.User>,
    HasTestUser<Authlete.User>,
    CanRequestForCredentialOffer<Authlete.User> {
    const val BASE_URL = "https://trial.authlete.net"
    const val WALLET_CLIENT_ID = "track1_light"
    val WalletRedirectURI = URI.create("https://nextdev-api.authlete.net/api/mock/redirection")

    override val testUser = User("inga", "inga")

    val LightProfileCredCfgId = CredentialConfigurationIdentifier("potential.light.profile")
    val IdentityCredentialCredCfgId = CredentialConfigurationIdentifier("IdentityCredential")
    val MdlCredCfgId = CredentialConfigurationIdentifier("org.iso.18013.5.1.mDL")

    override val issuerId = CredentialIssuerId(BASE_URL).getOrThrow()

    override val cfg: OpenId4VCIConfig
        get() = LightProfileCfg

    val LightProfileCfg = OpenId4VCIConfig(
        clientId = WALLET_CLIENT_ID,
        authFlowRedirectionURI = WalletRedirectURI,
        keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
        credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
        dPoPSigner = CryptoGenerator.ecProofSigner(),
        authorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
        clock = Clock.systemDefaultZone(),
    )

    data class User(val loginId: String, val password: String)

    val LightProfileCredentialOfferForm = CredentialOfferForm.authorizationCodeGrant(
        user = testUser,
        credentialConfigurationIds = setOf(LightProfileCredCfgId),
        issuerStateIncluded = true,
        credentialOfferEndpoint = "eudi-openid4vci://",
    )

    override suspend fun requestCredentialOffer(httpClient: HttpClient, form: CredentialOfferForm<User>): URI = coroutineScope {
        val url = "$BASE_URL/api/offer/issue"
        suspend fun HttpClient.visitOfferPage() = get(url).body<String>()
        suspend fun HttpClient.requestOffer(): String {
            val formParameters = Parameters.build {
                checkNotNull(form.user) { "User is required" }
                append("loginId", form.user.loginId)
                append("password", form.user.password)
                fun Set<CredentialConfigurationIdentifier>.toJson() = JsonArray(map { JsonPrimitive(it.value) })
                append("credentialConfigurationIds", form.credentialConfigurationIds.toJson().toString())
                if (form.authorizationCodeGrant != null) {
                    append("authorizationCodeGrantIncluded", "on")
                    if (form.authorizationCodeGrant.issuerStateIncluded) {
                        append("issuerStateIncluded", "on")
                    }
                }
                if (form.preAuthorizedCodeGrant != null) {
                    append("preAuthorizedCodeGrantIncluded", "on")
                    form.preAuthorizedCodeGrant.txCode?.let { append("txCode", it) }
                    append("txCodeInputMode", form.preAuthorizedCodeGrant.txCodeInputMode)
                    form.preAuthorizedCodeGrant.txCodeDescription?.let { append("txCodeDescription", it) }
                }
                if (form.credentialOfferEndpoint != null) {
                    append("credentialOfferEndpoint", form.credentialOfferEndpoint)
                }
            }
            return submitForm(url, formParameters).body<String>()
        }

        // Perform a GET to establish session
        val html = with(httpClient) {
            visitOfferPage()
            requestOffer()
        }
        absoluteHRefs(html).first { "?credential_offer=" in it }.let { URI.create(it) }
    }

    private suspend fun absoluteHRefs(html: String): List<String> = withContext(Dispatchers.IO) {
        Jsoup.parse(html)
            .select("a[href]") // select all hrefs
            .toList()
            .mapNotNull { it.attr("abs:href").toString() } // select absolute hrefs
    }

    override suspend fun HttpClient.authorizeIssuance(
        loginResponse: HttpResponse,
        user: User,
    ): HttpResponse {
        require(loginResponse.status.isSuccess())
        val formParameters = Parameters.build {
            append("loginId", user.loginId)
            append("password", user.password)
            append("authorized", "Authorize")
        }
        val url = "$BASE_URL/api/authorization/decision"
        return submitForm(url = url, formParameters)
    }
}

@DisplayName("Using Authlete trial Issuer, VCI Lib should be able to")
class AuthleteLightProfileTest {

    @Test
    fun `Resolve issuer's metadata`() = runTest {
        Authlete.testMetaDataResolution(enableHttLogging = false)
    }

    @Test
    fun `Place a request for a credential offer`() = runTest {
        val requestForCredentialOffer = Authlete.LightProfileCredentialOfferForm
        val credentialOffer = assertDoesNotThrow {
            createHttpClient(enableLogging = false).use { httpClient ->
                val credentialOfferUri = Authlete.requestCredentialOffer(httpClient, requestForCredentialOffer).toString()
                if (requestForCredentialOffer.credentialOfferEndpoint != null) {
                    assertTrue { credentialOfferUri.startsWith(requestForCredentialOffer.credentialOfferEndpoint) }
                }

                val resolver = DefaultCredentialOfferRequestResolver(httpClient)
                resolver.resolve(credentialOfferUri).getOrThrow()
            }
        }
        assertTrue("Missing crd cfg ids") {
            requestForCredentialOffer.credentialConfigurationIds.all {
                it in credentialOffer.credentialConfigurationIdentifiers
            }
        }
        assertEquals(
            requestForCredentialOffer.credentialConfigurationIds.size,
            credentialOffer.credentialConfigurationIdentifiers.size,
        )
        val grants = credentialOffer.grants
        assertNotNull(grants, "Missing grants")
        assertIs<Grants.AuthorizationCode>(grants)
        assertNotNull(grants.issuerState, "Missing issuer state")
    }

    @Test
    fun `Issue mso_mdoc credential using light profile`() = runBlocking {
        Authlete.testIssuanceWithAuthorizationCodeFlow(
            credCfgId = Authlete.LightProfileCredCfgId,
            enableHttLogging = false,
            claimSetToRequest = ::claimSetToRequest,
            popSignerPreference = ProofTypeMetaPreference.FavorCWT,
        )
    }

    @Test
    fun `Issue credential in sd-jwt-vc using authorization code grant`() = runTest {
        Authlete.testIssuanceWithAuthorizationCodeFlow(
            credCfgId = Authlete.IdentityCredentialCredCfgId,
            enableHttLogging = false,
            claimSetToRequest = ::claimSetToRequest,
        )
    }

    @Test
    fun `Issue credential in sd-jwt-vc using preAuthorizedCode grant`() = runBlocking {
        Authlete.testIssuanceWithPreAuthorizedCodeFlow(
            txCode = "HelloWorld",
            credCfgId = Authlete.IdentityCredentialCredCfgId,
            credentialOfferEndpoint = null,
            enableHttLogging = false,
            claimSetToRequest = ::claimSetToRequest,
        )
    }

    @Test
    fun `Issue mDL using authorization code grant`() = runBlocking {
        Authlete.testIssuanceWithAuthorizationCodeFlow(
            credCfgId = Authlete.MdlCredCfgId,
            enableHttLogging = false,
            claimSetToRequest = ::claimSetToRequest,
        )
    }

    @Test
    fun `Issue mDL using preAuthorizedCode grant`() = runBlocking {
        Authlete.testIssuanceWithPreAuthorizedCodeFlow(
            txCode = "123",
            credCfgId = Authlete.MdlCredCfgId,
            credentialOfferEndpoint = null,
            claimSetToRequest = ::claimSetToRequest,
        )
    }

    @Test
    fun `Issue multiple credentials in batch using authorization code grant`() = runBlocking {
        val credCfgIds = setOf(
            Authlete.IdentityCredentialCredCfgId,
            Authlete.MdlCredCfgId,
        )
        val credentialOfferUri = Authlete.requestAuthorizationCodeGrantOffer(credCfgIds)
        val issuer = assertDoesNotThrow {
            Authlete.createIssuer(credentialOfferUri.toString(), enableHttLogging = false)
        }
        assertTrue { credCfgIds.all { it in issuer.credentialOffer.credentialConfigurationIdentifiers } }
        val outcome = with(issuer) {
            val authorizedRequest = authorizeUsingAuthorizationCodeFlow(Authlete, enableHttLogging = false)
            submitBatchCredentialRequest(authorizedRequest, credCfgIds)
        }
        ensureIssued(outcome)
        Unit
    }
}

private suspend fun Issuer.submitBatchCredentialRequest(
    authorizedRequest: AuthorizedRequest,
    credentialConfigurationIds: Set<CredentialConfigurationIdentifier>,
): SubmittedRequest {
    val reqs = buildMap<IssuanceRequestPayload, PopSigner?> {
        for (credentialConfigurationId in credentialConfigurationIds) {
            //
            // This is a hack
            //
            val cfg = credentialOffer.credentialIssuerMetadata.credentialConfigurationsSupported[credentialConfigurationId]
            assertNotNull(cfg)
            val claimSetToRequest = claimSetToRequest(cfg)
            val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, claimSetToRequest)
            val popSigner = when (authorizedRequest) {
                is AuthorizedRequest.ProofRequired -> popSigner(credentialConfigurationId, ProofTypeMetaPreference.FavorJWT)
                is AuthorizedRequest.NoProofRequired -> null
            }
            put(requestPayload, popSigner)
        }
    }

    return when (authorizedRequest) {
        is AuthorizedRequest.ProofRequired -> with(authorizedRequest) {
            requestBatch(reqs.mapValues { (_, v) -> checkNotNull(v) }.toList())
        }

        is AuthorizedRequest.NoProofRequired -> with(authorizedRequest) {
            requestBatch(reqs.keys.toList())
        }
    }.getOrThrow()
}

/**
 * This is specific behavior to the Authlete's issuer, when issuing mso_mdoc credential,
 * Normally, claimSet is optional
 * If not set, Authlete's Issuer sends back a 400-response reporting that
 * the user has no permission.
 */
private fun claimSetToRequest(
    credCfg: CredentialConfiguration,
): ClaimSet? {
    return when (credCfg) {
        is MsoMdocCredential -> credCfg.claims.toClaimSet()
        else -> null
    }
}
