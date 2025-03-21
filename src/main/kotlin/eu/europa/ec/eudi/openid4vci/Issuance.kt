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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.json.JsonObject

/**
 * Represents the credential as it is serialized by the credential issuer
 * within a credential or deferred response.
 *
 * The choice is format-specific, and it can be either a string or a JSON object
 */
sealed interface Credential {
    @JvmInline
    value class Str(val value: String) : Credential {
        override fun toString(): String = value
    }

    @JvmInline
    value class Json(val value: JsonObject) : Credential {
        override fun toString(): String = value.toString()
    }
}

/**
 *  Credential was issued from server and the result is returned inline.
 *
 * @param credential The issued credential.
 * @param additionalInfo Optional, information returned by the issuer for the [credential]
 */
data class IssuedCredential(
    val credential: Credential,
    val additionalInfo: JsonObject?,
) : java.io.Serializable {
    companion object {
        fun string(credential: String, additionalInfo: JsonObject? = null): IssuedCredential =
            IssuedCredential(Credential.Str(credential), additionalInfo)

        fun json(credential: JsonObject, additionalInfo: JsonObject? = null): IssuedCredential =
            IssuedCredential(Credential.Json(credential), additionalInfo)
    }
}

/**
 * Sealed hierarchy of states describing the state of an issuance request submitted to a credential issuer.
 */
sealed interface SubmissionOutcome : java.io.Serializable {

    /**
     * State that denotes the successful submission of an issuance request
     * @param credentials The outcome of the issuance request.
     * If the issuance request was a batch request, it will contain the results of each issuance request.
     * If it was a single issuance request list will contain only one result.
     *
     * @param credentials The credentials issued
     * @param notificationId The identifier to be used in issuer's notification endpoint.
     */
    data class Success(
        val credentials: List<IssuedCredential>,
        val notificationId: NotificationId?,
    ) : SubmissionOutcome {
        init {
            require(credentials.isNotEmpty()) { "credentials must not be empty" }
        }
    }

    /**
     * Credential could not be issued immediately. An identifier is returned from server to be used later on
     * to request the credential from issuer's Deferred Credential Endpoint.
     *
     * @param transactionId  A string identifying a Deferred Issuance transaction.
     */
    data class Deferred(val transactionId: TransactionId) : SubmissionOutcome

    /**
     * State that denotes that the credential issuance request has failed
     *
     * @param error The error that caused the failure of the request
     */
    data class Failed(val error: CredentialIssuanceError) : SubmissionOutcome
}

/**
 * Sealed interface to model the payload of an issuance request. Issuance can be requested by providing the credential configuration
 * identifier and a claim set ot by providing a credential identifier retrieved from token endpoint while authorizing an issuance request.
 */
sealed interface IssuanceRequestPayload {

    val credentialConfigurationIdentifier: CredentialConfigurationIdentifier

    /**
     * Credential identifier based request payload.
     *
     * @param credentialConfigurationIdentifier The credential configuration identifier
     * @param credentialIdentifier  The credential identifier
     */
    data class IdentifierBased(
        override val credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
        val credentialIdentifier: CredentialIdentifier,
    ) : IssuanceRequestPayload

    /**
     * Credential configuration based request payload.
     *
     * @param credentialConfigurationIdentifier The credential configuration identifier
     */
    data class ConfigurationBased(
        override val credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
    ) : IssuanceRequestPayload
}

typealias AuthorizedRequestAnd<T> = Pair<AuthorizedRequest, T>

/**
 * An interface for submitting a credential issuance request.
 */
interface RequestIssuance {

    /**
     * Places a request to the credential issuance endpoint.
     *
     * @param requestPayload the payload of the request
     * @param popSigners one or more signers for the proofs to be sent. Required when requested credential's configuration requires proof.
     * @return the possibly updated [AuthorizedRequest] (if updated it will contain a fresh updated Resource-Server DPoP Nonce)
     * and the [SubmissionOutcome]
     */
    suspend fun AuthorizedRequest.request(
        requestPayload: IssuanceRequestPayload,
        popSigners: List<PopSigner> = emptyList(),
    ): Result<AuthorizedRequestAnd<SubmissionOutcome>>
}

sealed interface PopSigner {
    /**
     * A signer for proof of possession JWTs
     * @param algorithm The algorithm used by the singing key
     * @param bindingKey The public key to be included to the proof. It should correspond to the key
     * used to sign the proof.
     * @param jwsSigner A function to sign the JWT
     */
    data class Jwt(
        val algorithm: JWSAlgorithm,
        val bindingKey: JwtBindingKey,
        val jwsSigner: JWSSigner,
    ) : PopSigner

    companion object {

        /**
         * Factory method for creating a [PopSigner.Jwt]
         *
         * Comes handy when caller has access to [privateKey]
         *
         * @param privateKey the key that will be used to sign the JWT
         * @param publicKey the pub key to be included in the JWT. It should form a pair with [privateKey].
         * In case of [JwtBindingKey.Did] this condition is not being checked.
         * @param algorithm The algorithm for signing the JWT
         *
         * @return the JWT signer
         */
        fun jwtPopSigner(
            privateKey: JWK,
            algorithm: JWSAlgorithm,
            publicKey: JwtBindingKey,
        ): Jwt {
            require(privateKey.isPrivate) { "A private key is required" }
            require(
                when (publicKey) {
                    is JwtBindingKey.Did -> true // Would require DID resolution which is out of scope
                    is JwtBindingKey.Jwk -> privateKey.toPublicJWK() == publicKey.jwk
                    is JwtBindingKey.X509 -> privateKey.toPublicJWK() == JWK.parse(publicKey.chain.first())
                },
            ) { "Public/private key don't match" }

            val signer = DefaultJWSSignerFactory().createJWSSigner(privateKey, algorithm)
            return Jwt(algorithm, publicKey, signer)
        }
    }
}

/**
 * A factory method that based on the issuer's supported encryption and the wallet's configuration creates the encryption specification
 * that the wallet expects in the response of its issuance request.
 */
typealias ResponseEncryptionSpecFactory =
    (SupportedEncryptionAlgorithmsAndMethods, KeyGenerationConfig) -> IssuanceResponseEncryptionSpec?

/**
 * Errors that can happen in the process of issuance process
 */
sealed class CredentialIssuanceError(message: String) : Throwable(message) {

    /**
     * Indicates that the state returned by the authorization server doesn't match the state
     * included which was included in the authorization request, during authorization code flow
     */
    class InvalidAuthorizationState : CredentialIssuanceError("InvalidAuthorizationState")

    /**
     * Failure when placing Pushed Authorization Request to Authorization Server
     */
    data class PushedAuthorizationRequestFailed(
        val error: String,
        val errorDescription: String?,
    ) : CredentialIssuanceError("$error+${errorDescription?.let { " description=$it" }}")

    /**
     * Failure when requesting access token from Authorization Server
     */
    data class AccessTokenRequestFailed(
        val error: String,
        val errorDescription: String?,
    ) : CredentialIssuanceError("$error+${errorDescription?.let { " description=$it" }}")

    /**
     * Failure when creating an issuance request
     */
    class InvalidIssuanceRequest(
        message: String,
    ) : CredentialIssuanceError(message)

    /**
     * Issuer rejected the issuance request because no or invalid proof(s) were provided or at least one of the key proofs does
     * not contain a c_nonce value.
     */
    data class InvalidProof(
        val errorDescription: String? = null,
    ) : CredentialIssuanceError("Invalid Proof")

    /**
     * Issuer rejected the issuance request because considered the proof erroneous.
     * It is marked as irrecoverable because it is raised only after the library
     * has automatically retried to recover from an [InvalidProof] error and failed
     */
    data class IrrecoverableInvalidProof(val errorDescription: String? = null) :
        CredentialIssuanceError("Irrecoverable invalid proof ")

    /**
     * Issuer has not issued yet deferred credential. Retry interval (in seconds) is provided to caller
     */
    data class DeferredCredentialIssuancePending(
        val retryInterval: Long = 5,
    ) : CredentialIssuanceError("DeferredCredentialIssuancePending")

    /**
     * Invalid access token passed to issuance server
     */
    class InvalidToken : CredentialIssuanceError("InvalidToken")

    /**
     * Invalid transaction id passed to issuance server in the context of deferred credential requests
     */
    class InvalidTransactionId : CredentialIssuanceError("InvalidTransactionId")

    /**
     * Invalid credential type requested to issuance server
     */
    class UnsupportedCredentialType : CredentialIssuanceError("UnsupportedCredentialType")

    /**
     * Unsupported credential type requested to issuance server
     */
    class UnsupportedCredentialFormat : CredentialIssuanceError("UnsupportedCredentialFormat")

    /**
     * Invalid encryption parameters passed to issuance server
     */
    class InvalidEncryptionParameters : CredentialIssuanceError("InvalidEncryptionParameters")

    /**
     * Issuance server does not support batch credential requests
     */
    class IssuerDoesNotSupportBatchIssuance : CredentialIssuanceError("IssuerDoesNotSupportBatchIssuance")

    /**
     * Issuance server provides supports batch_size which is
     * smaller than the number of [PopSigner] the caller provided.
     */
    class IssuerBatchSizeLimitExceeded(val batchSize: Int) :
        CredentialIssuanceError("IssuerBatchSizeLimitExceeded $batchSize")

    /**
     * Issuance server does not support deferred credential issuance
     */
    class IssuerDoesNotSupportDeferredIssuance : CredentialIssuanceError("IssuerDoesNotSupportDeferredIssuance")

    /**
     * Generic failure during issuance request
     */
    data class IssuanceRequestFailed(
        val error: String,
        val errorDescription: String? = null,
    ) : CredentialIssuanceError("$error+${errorDescription?.let { " description=$it" }}")

    /**
     * Generic failure during notification
     */
    data class NotificationFailed(
        val error: String,
    ) : CredentialIssuanceError(error)

    /**
     * Issuance server response is un-parsable
     */
    data class ResponseUnparsable(val error: String) : CredentialIssuanceError("ResponseUnparsable")

    /**
     * Request to nonce endpoint of issuer failed
     */
    data class CNonceRequestFailed(val error: String) : CredentialIssuanceError("CNonceRequestFailed")

    /**
     * Sealed hierarchy of errors related to proof generation
     */
    sealed class ProofGenerationError(message: String) : CredentialIssuanceError(message) {

        /**
         * Proof type provided for specific credential is not supported from issuance server
         */
        class ProofTypeNotSupported : ProofGenerationError("ProofTypeNotSupported")

        /**
         * Proof type signing algorithm provided for specific credential is not supported from issuance server
         */
        class ProofTypeSigningAlgorithmNotSupported :
            ProofGenerationError("ProofTypeSigningAlgorithmNotSupported")
    }

    /**
     * Sealed hierarchy of errors related to validation of encryption parameters passed along with the issuance request.
     */
    sealed class ResponseEncryptionError(message: String) : CredentialIssuanceError(message) {

        /**
         * Wallet requires Credential Response encryption, but it is not supported by the issuance server.
         */
        class ResponseEncryptionRequiredByWalletButNotSupportedByIssuer :
            ResponseEncryptionError("ResponseEncryptionRequiredByWalletButNotSupportedByIssuer")

        /**
         * Response encryption algorithm specified in request is not supported from issuance server
         */
        class ResponseEncryptionAlgorithmNotSupportedByIssuer :
            ResponseEncryptionError("ResponseEncryptionAlgorithmNotSupportedByIssuer")

        /**
         * Response encryption method specified in request is not supported from issuance server
         */
        class ResponseEncryptionMethodNotSupportedByIssuer :
            ResponseEncryptionError("ResponseEncryptionMethodNotSupportedByIssuer")

        /**
         * Issuer enforces encrypted responses but encryption parameters not provided in request
         */
        class IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided :
            ResponseEncryptionError("IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided")

        /**
         * Wallet requires Credential Response encryption, but no crypto material can be generated for the issuance server.
         */
        class WalletRequiresCredentialResponseEncryptionButNoCryptoMaterialCanBeGenerated :
            ResponseEncryptionError("WalletRequiresCredentialResponseEncryptionButNoCryptoMaterialCanBeGenerated")
    }

    /**
     * Wrong content-type of encrypted response. Content-type of encrypted responses must be application/jwt
     */
    data class InvalidResponseContentType(
        val expectedContentType: String,
        val invalidContentType: String,
    ) : CredentialIssuanceError(
        "Encrypted response content-type expected to be $expectedContentType but instead was $invalidContentType",
    )
}
