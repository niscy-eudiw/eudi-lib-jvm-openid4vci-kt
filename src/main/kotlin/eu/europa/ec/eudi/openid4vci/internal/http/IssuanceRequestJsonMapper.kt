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
package eu.europa.ec.eudi.openid4vci.internal.http

import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.*
import eu.europa.ec.eudi.openid4vci.internal.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

//
// Credential request / response
//
@Serializable
internal data class CredentialResponseEncryptionSpecTO(
    @SerialName("jwk") val jwk: JsonObject,
    @SerialName("alg") val encryptionAlgorithm: String,
    @SerialName("enc") val encryptionMethod: String,
) {
    companion object {

        fun from(responseEncryption: IssuanceResponseEncryptionSpec): CredentialResponseEncryptionSpecTO {
            val credentialEncryptionJwk =
                Json.parseToJsonElement(responseEncryption.jwk.toPublicJWK().toString()).jsonObject
            val credentialResponseEncryptionAlg = responseEncryption.algorithm.toString()
            val credentialResponseEncryptionMethod = responseEncryption.encryptionMethod.toString()
            return CredentialResponseEncryptionSpecTO(
                credentialEncryptionJwk,
                credentialResponseEncryptionAlg,
                credentialResponseEncryptionMethod,
            )
        }
    }
}

@Serializable
internal data class CredentialDefinitionTO(
    @SerialName("type") val type: List<String>,
    @SerialName("credentialSubject") val credentialSubject: JsonObject? = null,
)

@Serializable
data class ProofsTO(
    @SerialName("jwt") val jwtProofs: List<String>? = null,
    @SerialName("ldp_vp") val ldpVpProofs: List<String>? = null,
) {

    init {
        require(!(jwtProofs.isNullOrEmpty() && ldpVpProofs.isNullOrEmpty()))
    }
}

@Serializable
internal data class CredentialRequestTO(
    @SerialName("credential_identifier") val credentialIdentifier: String? = null,
    @SerialName("format") val format: String? = null,
    @SerialName("doctype") val docType: String? = null,
    @SerialName("vct") val vct: String? = null,
    @SerialName("proof") val proof: Proof? = null,
    @SerialName("proofs") val proofs: ProofsTO? = null,
    @SerialName("credential_response_encryption") val credentialResponseEncryption: CredentialResponseEncryptionSpecTO? = null,
    @SerialName("claims") val claims: JsonObject? = null,
    @SerialName("credential_definition") val credentialDefinition: CredentialDefinitionTO? = null,
) {
    init {
        require(format != null || credentialIdentifier != null) { "Either format or credentialIdentifier must be set" }
        require(!(proof != null && proofs != null)) {
            "On of proof or proofs must be provided"
        }
    }

    companion object {

        fun from(
            credential: CredentialType.MsoMdocDocType,
            proofs: List<Proof>,
            encryption: IssuanceResponseEncryptionSpec?,
        ): CredentialRequestTO {
            val (p, ps) = proofs.proofOrProofs()
            return CredentialRequestTO(
                format = FORMAT_MSO_MDOC,
                proof = p,
                proofs = ps,
                credentialResponseEncryption = encryption?.let(CredentialResponseEncryptionSpecTO::from),
                docType = credential.doctype,
                claims = credential.claimSet?.let {
                    Json.encodeToJsonElement(it).jsonObject
                },
            )
        }

        fun from(
            credential: CredentialType.SdJwtVcType,
            proofs: List<Proof>,
            encryption: IssuanceResponseEncryptionSpec?,
        ): CredentialRequestTO {
            val (p, ps) = proofs.proofOrProofs()
            return CredentialRequestTO(
                format = FORMAT_SD_JWT_VC,
                proof = p,
                proofs = ps,
                credentialResponseEncryption = encryption?.let(CredentialResponseEncryptionSpecTO::from),
                vct = credential.type,
                claims = credential.claims?.let {
                    buildJsonObject {
                        it.claims.forEach { claimName ->
                            put(claimName, JsonObject(emptyMap()))
                        }
                    }
                },
            )
        }

        fun from(
            credential: CredentialType.W3CSignedJwtType,
            proofs: List<Proof>,
            encryption: IssuanceResponseEncryptionSpec?,
        ): CredentialRequestTO {
            val (p, ps) = proofs.proofOrProofs()
            return CredentialRequestTO(
                format = FORMAT_W3C_SIGNED_JWT,
                proof = p,
                proofs = ps,
                credentialResponseEncryption = encryption?.let(CredentialResponseEncryptionSpecTO::from),
                credentialDefinition = CredentialDefinitionTO(
                    type = credential.type,
                    credentialSubject = credential.claims?.let {
                        buildJsonObject {
                            it.claims.forEach { claimName ->
                                put(claimName, JsonObject(emptyMap()))
                            }
                        }
                    },
                ),
            )
        }

        fun from(
            credentialIdentifier: CredentialIdentifier,
            proofs: List<Proof>,
            encryption: IssuanceResponseEncryptionSpec?,
        ): CredentialRequestTO {
            val (p, ps) = proofs.proofOrProofs()
            return CredentialRequestTO(
                credentialIdentifier = credentialIdentifier.value,
                proof = p,
                proofs = ps,
                credentialResponseEncryption = encryption?.let(CredentialResponseEncryptionSpecTO::from),
            )
        }

        fun from(request: CredentialIssuanceRequest): CredentialRequestTO {
            val (ref, proofs, encryption) = request
            return when (ref) {
                is CredentialConfigurationReference.ByFormat ->
                    when (val credential = ref.credential) {
                        is CredentialType.MsoMdocDocType -> from(credential, proofs, encryption)
                        is CredentialType.SdJwtVcType -> from(credential, proofs, encryption)
                        is CredentialType.W3CSignedJwtType -> from(credential, proofs, encryption)
                    }

                is CredentialConfigurationReference.ById -> from(ref.credentialIdentifier, proofs, encryption)
            }
        }

        private fun List<Proof>?.proofOrProofs(): Pair<Proof?, ProofsTO?> =
            if (this.isNullOrEmpty()) null to null
            else if (size == 1) first() to null
            else null to ProofsTO(
                jwtProofs = filterIsInstance<Proof.Jwt>().map { it.jwt.serialize() }.takeIf { it.isNotEmpty() },
                ldpVpProofs = filterIsInstance<Proof.LdpVp>().map { it.ldpVp }.takeIf { it.isNotEmpty() },
            )
    }
}

@Serializable
internal data class CredentialResponseSuccessTO(
    @SerialName("credential") val credential: JsonElement? = null,
    @SerialName("credentials") val credentials: JsonArray? = null,
    @SerialName("transaction_id") val transactionId: String? = null,
    @SerialName("notification_id") val notificationId: String? = null,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long? = null,
) {
    init {
        if (credential != null) {
            ensureNotNull(issuedCredentialOf(credential)) {
                throw ResponseUnparsable("credential could be either a string or a json object")
            }
        }
        if (!credentials.isNullOrEmpty()) {
            credentials.forEach { credential ->
                ensureNotNull(issuedCredentialOf(credential)) {
                    throw ResponseUnparsable("credential could be either a string or a json object")
                }
            }
        }
        ensure(!(credential != null && !credentials.isNullOrEmpty())) {
            ResponseUnparsable("Only one of credential or credentials can be present")
        }
        if (transactionId != null) {
            ensure(credential == null && credentials.isNullOrEmpty()) {
                ResponseUnparsable("transaction_id must not be used if credential or credentials is present")
            }
        }
        if (notificationId != null) {
            ensure(credential != null || !credentials.isNullOrEmpty()) {
                ResponseUnparsable("notification_id can be present, if credential or credentials is present")
            }
        }
    }

    fun toDomain(): SubmissionOutcomeInternal {
        val cNonce = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) }
        val transactionId = transactionId?.let { TransactionId(it) }
        val notificationId = notificationId?.let(::NotificationId)

        val issuedCredentials =
            when {
                credential != null -> listOf(checkNotNull(issuedCredentialOf(credential)))
                !credentials.isNullOrEmpty() -> credentials.map { credential ->
                    checkNotNull(issuedCredentialOf(credential))
                }

                else -> emptyList()
            }

        return when {
            issuedCredentials.isNotEmpty() -> SubmissionOutcomeInternal.Success(
                issuedCredentials,
                cNonce,
                notificationId,
            )

            transactionId != null -> SubmissionOutcomeInternal.Deferred(transactionId, cNonce)
            else -> error("Cannot happen")
        }
    }

    companion object {

        fun from(jwtClaimsSet: JWTClaimsSet): CredentialResponseSuccessTO {
            val claims = jwtClaimsSet.asJsonObject()
            return CredentialResponseSuccessTO(
                credential = claims["credential"],
                credentials = claims["credentials"] as? JsonArray,
                transactionId = jwtClaimsSet.getStringClaim("transaction_id"),
                notificationId = jwtClaimsSet.getStringClaim("notification_id"),
                cNonce = jwtClaimsSet.getStringClaim("c_nonce"),
                cNonceExpiresInSeconds = jwtClaimsSet.getLongClaim("c_nonce_expires_in"),
            )
        }
    }
}

private fun JWTClaimsSet.asJsonObject(): JsonObject {
    val json = Json.parseToJsonElement(toString())
    check(json is JsonObject)
    return json
}

private fun issuedCredentialOf(json: JsonElement): IssuedCredential? {
    fun credentialOf(json: JsonElement): Credential? = when {
        json is JsonPrimitive && json.isString -> Credential.Str(json.content)
        json is JsonObject && json.isNotEmpty() -> Credential.Json(json)
        else -> null
    }
    // This would change in draft 15
    return credentialOf(json)?.let { IssuedCredential(it, null) }
}

//
// Deferred request / response
//

@Serializable
internal data class DeferredRequestTO(
    @SerialName("transaction_id") val transactionId: String,
)

@Serializable
internal data class DeferredIssuanceSuccessResponseTO(
    @SerialName("credential") val credential: JsonElement? = null,
    @SerialName("credentials") val credentials: JsonArray? = null,
    @SerialName("notification_id") val notificationId: String? = null,
) {
    fun toDomain(): DeferredCredentialQueryOutcome.Issued {
        val notificationId = notificationId?.let { NotificationId(it) }
        val credentials = when {
            credential is JsonPrimitive && credential.contentOrNull != null && credentials == null -> listOf(credential)
            credential == null && !credentials.isNullOrEmpty() -> credentials
            else -> error("One of credential or credentials must be present")
        }.map { requireNotNull(issuedCredentialOf(it)) }

        return DeferredCredentialQueryOutcome.Issued(credentials, notificationId)
    }

    companion object {
        fun from(jwtClaimsSet: JWTClaimsSet): DeferredIssuanceSuccessResponseTO {
            val claims = jwtClaimsSet.asJsonObject()
            return DeferredIssuanceSuccessResponseTO(
                credential = claims["credential"],
                credentials = claims["credentials"] as? JsonArray,
                notificationId = jwtClaimsSet.getStringClaim("notification_id"),
            )
        }
    }
}

//
// Notification
//

@Serializable
internal class NotificationTO(
    @SerialName("notification_id") val id: String,
    @SerialName("event") val event: NotificationEventTO,
    @SerialName("event_description") val description: String? = null,
) {
    companion object {
        fun from(credentialIssuanceEvent: CredentialIssuanceEvent): NotificationTO =
            when (credentialIssuanceEvent) {
                is CredentialIssuanceEvent.Accepted -> NotificationTO(
                    id = credentialIssuanceEvent.id.value,
                    event = NotificationEventTO.CREDENTIAL_ACCEPTED,
                    description = credentialIssuanceEvent.description,
                )

                is CredentialIssuanceEvent.Deleted -> NotificationTO(
                    id = credentialIssuanceEvent.id.value,
                    event = NotificationEventTO.CREDENTIAL_DELETED,
                    description = credentialIssuanceEvent.description,
                )

                is CredentialIssuanceEvent.Failed -> NotificationTO(
                    id = credentialIssuanceEvent.id.value,
                    event = NotificationEventTO.CREDENTIAL_FAILURE,
                    description = credentialIssuanceEvent.description,
                )
            }
    }
}

@Serializable
internal enum class NotificationEventTO {
    @SerialName("credential_accepted")
    CREDENTIAL_ACCEPTED,

    @SerialName("credential_failure")
    CREDENTIAL_FAILURE,

    @SerialName("credential_deleted")
    CREDENTIAL_DELETED,
}

//
// Error response
//

@Serializable
internal data class GenericErrorResponseTO(
    @SerialName("error") val error: String,
    @SerialName("error_description") val errorDescription: String? = null,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long? = null,
    @SerialName("interval") val interval: Long? = null,
) {

    fun toIssuanceError(): CredentialIssuanceError = when (error) {
        "invalid_proof" ->
            cNonce
                ?.let { InvalidProof(cNonce, cNonceExpiresInSeconds, errorDescription) }
                ?: ResponseUnparsable("Issuer responded with invalid_proof error but no c_nonce was provided")

        "issuance_pending" ->
            interval
                ?.let { DeferredCredentialIssuancePending(interval) }
                ?: DeferredCredentialIssuancePending()

        "invalid_token" -> InvalidToken()
        "invalid_transaction_id " -> InvalidTransactionId()
        "unsupported_credential_type " -> UnsupportedCredentialType()
        "unsupported_credential_format " -> UnsupportedCredentialFormat()
        "invalid_encryption_parameters " -> InvalidEncryptionParameters()
        else -> IssuanceRequestFailed(error, errorDescription)
    }

    fun toDeferredCredentialQueryOutcome(): DeferredCredentialQueryOutcome =
        when (error) {
            "issuance_pending" -> DeferredCredentialQueryOutcome.IssuancePending(interval)
            else -> DeferredCredentialQueryOutcome.Errored(error, errorDescription)
        }
}
