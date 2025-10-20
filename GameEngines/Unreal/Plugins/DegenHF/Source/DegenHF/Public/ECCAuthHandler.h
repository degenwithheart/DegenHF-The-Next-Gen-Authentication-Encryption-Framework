#pragma once

#include "CoreMinimal.h"
#include "UObject/Object.h"
#include "UObject/NoExportTypes.h"
#include "Interfaces/IHttpRequest.h"
#include "ECCAuthHandler.generated.h"

/**
 * ECC-based authentication handler for Unreal Engine
 * Provides blockchain-grade security for UE games
 */
UCLASS(BlueprintType, Category = "DegenHF|Authentication")
class DEGENHF_API UECCAuthHandler : public UObject
{
	GENERATED_BODY()

public:
	UECCAuthHandler();

	/**
	 * Initialize the authentication handler
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	void Initialize();

	/**
	 * Register a new user with ECC-secured password hashing
	 * @param Username - The username to register
	 * @param Password - The password to hash and store
	 * @param OutUserId - The generated user ID
	 * @return True if registration successful
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	bool RegisterUser(const FString& Username, const FString& Password, FString& OutUserId);

	/**
	 * Authenticate a user and return a JWT token
	 * @param Username - The username to authenticate
	 * @param Password - The password to verify
	 * @param OutToken - The JWT token if authentication successful
	 * @return True if authentication successful
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	bool AuthenticateUser(const FString& Username, const FString& Password, FString& OutToken);

	/**
	 * Verify a JWT token and return user claims
	 * @param Token - The JWT token to verify
	 * @param OutClaims - The user claims if token is valid
	 * @return True if token is valid
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	bool VerifyToken(const FString& Token, FString& OutUserId, FString& OutUsername);

	/**
	 * Create a secure session
	 * @param UserId - The user ID for the session
	 * @param OutSessionId - The generated session ID
	 * @return True if session created successfully
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	bool CreateSession(const FString& UserId, FString& OutSessionId);

	/**
	 * Get session data
	 * @param SessionId - The session ID to retrieve
	 * @param OutUserId - The user ID associated with the session
	 * @param OutUsername - The username associated with the session
	 * @return True if session is valid and found
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	bool GetSession(const FString& SessionId, FString& OutUserId, FString& OutUsername);

	/**
	 * Check if a user is currently logged in
	 * @return True if user has a valid session
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	bool IsUserLoggedIn() const;

	/**
	 * Get the current user's ID
	 * @return Current user ID or empty string if not logged in
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	FString GetCurrentUserId() const;

	/**
	 * Get the current user's name
	 * @return Current username or empty string if not logged in
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	FString GetCurrentUsername() const;

	/**
	 * Logout the current user
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	void Logout();

	/**
	 * Save authentication data to disk (for persistence)
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	void SaveAuthData();

	/**
	 * Load authentication data from disk
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	void LoadAuthData();

private:
	/** ECC Private Key */
	TArray<uint8> PrivateKey;

	/** ECC Public Key */
	TArray<uint8> PublicKey;

	/** Token cache for performance */
	TMap<FString, FString> TokenCache;

	/** Session cache */
	TMap<FString, FString> SessionCache;

	/** Current user session data */
	FString CurrentUserId;
	FString CurrentUsername;
	FString CurrentToken;

	/** Configuration */
	int32 HashIterations;
	float TokenExpiryHours;
	float CacheExpiryMinutes;

	/** Helper functions */
	bool HashPassword(const FString& Password, TArray<uint8>& OutSalt, TArray<uint8>& OutHash);
	bool VerifyPassword(const FString& Password, const TArray<uint8>& Salt, const TArray<uint8>& Hash);
	FString GenerateToken(const FString& UserId, const FString& Username);
	bool ValidateToken(const FString& Token, FString& OutUserId, FString& OutUsername);
	FString GenerateSimpleToken(const FString& UserId, const FString& Username);

	/** ECC Cryptography helpers */
	bool GenerateECCKeyPair();
	bool SignData(const TArray<uint8>& Data, TArray<uint8>& OutSignature);
	bool VerifySignature(const TArray<uint8>& Data, const TArray<uint8>& Signature);

	/** Utility functions */
	FString GenerateUserId();
	FString GenerateSessionId();
	int64 GetCurrentTimestamp();
	bool IsTokenExpired(int64 TokenTimestamp, float ExpiryHours);
};