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
package eu.europa.ec.eudi.openid4vci

import org.apache.http.client.utils.URIBuilder
import org.junit.jupiter.api.Assertions
import kotlin.test.Test

internal class CredentialOfferRequestTest {

    @Test
    internal fun `Fails with non parsable Credential Offer Endpoint URL`() {
        CredentialOfferRequest("file:")
            .fold(
                { Assertions.fail("Credential Offer Endpoint URL should not have been parsed") },
                {
                    val error = Assertions.assertInstanceOf(CredentialOfferRequestException::class.java, it)
                    Assertions.assertInstanceOf(
                        CredentialOfferRequestError.NonParsableCredentialOfferEndpointUrl::class.java,
                        error.error,
                    )
                },
            )
    }

    @Test
    internal fun `Fails when neither 'credential_offer' nor 'credential_offer_uri' is provided`() {
        CredentialOfferRequest("wallet://credential_offer")
            .fold(
                { Assertions.fail("Credential Offer Endpoint URL should not have been parsed") },
                {
                    val error = Assertions.assertInstanceOf(CredentialOfferRequestException::class.java, it)
                    Assertions.assertInstanceOf(
                        CredentialOfferRequestValidationError.OneOfCredentialOfferOrCredentialOfferUri::class.java,
                        error.error,
                    )
                },
            )
    }

    @Test
    internal fun `Fails when both 'credential_offer' and 'credential_offer_uri' are provided `() {
        val uri = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", "{}")
            .addParameter("credential_offer_uri", "https://credential.offer/1")
            .build()
        CredentialOfferRequest(uri.toString())
            .fold(
                { Assertions.fail("Credential Offer Endpoint URL should not have been parsed") },
                {
                    val error = Assertions.assertInstanceOf(CredentialOfferRequestException::class.java, it)
                    Assertions.assertInstanceOf(
                        CredentialOfferRequestValidationError.OneOfCredentialOfferOrCredentialOfferUri::class.java,
                        error.error,
                    )
                },
            )
    }

    @Test
    internal fun `PassByValue is created when 'credential_offer' parameter is provided`() {
        val credentialOffer = """
            {
               "credential_issuer": "https://credential-issuer.example.com",
               "credentials": [
                  "UniversityDegree_JWT",
                  {
                     "format": "mso_mdoc",
                     "doctype": "org.iso.18013.5.1.mDL"
                  }
               ],
               "grants": {
                  "authorization_code": {
                     "issuer_state": "eyJhbGciOiJSU0Et...FYUaBy"
                  },
                  "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                     "pre-authorized_code": "adhjhdjajkdkhjhdj",
                     "user_pin_required": true
                  }
               }
            }
        """.trimIndent()

        val credentialOfferEndpointUri = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", credentialOffer)
            .build()

        CredentialOfferRequest(credentialOfferEndpointUri.toString())
            .fold(
                {
                    val passByValue = Assertions.assertInstanceOf(CredentialOfferRequest.PassByValue::class.java, it)
                    Assertions.assertEquals(credentialOffer, passByValue.value)
                },
                { Assertions.fail("Credential Offer Endpoint URL should not have been parsed") },
            )
    }

    @Test
    internal fun `PassByReference cannot be created when 'credential_offer_uri' is not an HTTPS URL`() {
        val credentialOfferUri = "http://credential.offer/1"
        val credentialOfferEndpointUri = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer_uri", credentialOfferUri)
            .build()
        CredentialOfferRequest(credentialOfferEndpointUri.toString())
            .fold(
                { Assertions.fail("Credential Offer Endpoint URL should not have been parsed") },
                {
                    val error = Assertions.assertInstanceOf(CredentialOfferRequestException::class.java, it)
                    Assertions.assertInstanceOf(
                        CredentialOfferRequestValidationError.InvalidCredentialOfferUri::class.java,
                        error.error,
                    )
                },
            )
    }

    @Test
    internal fun `PassByReference is be created when 'credential_offer_uri' is an HTTPS URL`() {
        val credentialOfferUri = "https://credential.offer/1"
        val credentialOfferEndpointUri = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer_uri", credentialOfferUri)
            .build()
        CredentialOfferRequest(credentialOfferEndpointUri.toString())
            .fold(
                {
                    val passByReference =
                        Assertions.assertInstanceOf(CredentialOfferRequest.PassByReference::class.java, it)
                    Assertions.assertEquals(credentialOfferUri, passByReference.value.value.toString())
                },
                {
                    Assertions.fail("Credential Offer Endpoint URL should have been parsed")
                },
            )
    }
}