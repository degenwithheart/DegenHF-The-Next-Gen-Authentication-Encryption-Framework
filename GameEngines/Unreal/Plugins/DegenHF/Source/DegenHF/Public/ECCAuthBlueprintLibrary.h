#pragma once

#include "CoreMinimal.h"
#include "Kismet/BlueprintFunctionLibrary.h"
#include "ECCAuthBlueprintLibrary.generated.h"

/**
 * Blueprint function library for DegenHF ECC Authentication
 * Provides easy access to authentication functions from Blueprints
 */
UCLASS()
class DEGENHF_API UECCAuthBlueprintLibrary : public UBlueprintFunctionLibrary
{
	GENERATED_BODY()

public:
	/**
	 * Get the global ECC authentication handler instance
	 * @return The ECC auth handler instance
	 */
	UFUNCTION(BlueprintPure, Category = "DegenHF|Authentication")
	static class UECCAuthHandler* GetECCAuthHandler();

	/**
	 * Register a new user (Blueprint-friendly wrapper)
	 * @param Username - The username to register
	 * @param Password - The password for the user
	 * @param UserId - The generated user ID
	 * @param Success - Whether registration was successful
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	static void RegisterUser(const FString& Username, const FString& Password, FString& UserId, bool& Success);

	/**
	 * Authenticate a user (Blueprint-friendly wrapper)
	 * @param Username - The username to authenticate
	 * @param Password - The password to verify
	 * @param Token - The JWT token if authentication successful
	 * @param Success - Whether authentication was successful
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	static void AuthenticateUser(const FString& Username, const FString& Password, FString& Token, bool& Success);

	/**
	 * Verify a token (Blueprint-friendly wrapper)
	 * @param Token - The token to verify
	 * @param UserId - The user ID from the token
	 * @param Username - The username from the token
	 * @param IsValid - Whether the token is valid
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	static void VerifyToken(const FString& Token, FString& UserId, FString& Username, bool& IsValid);

	/**
	 * Check if user is logged in (Blueprint-friendly wrapper)
	 * @return True if user is logged in
	 */
	UFUNCTION(BlueprintPure, Category = "DegenHF|Authentication")
	static bool IsUserLoggedIn();

	/**
	 * Get current user ID (Blueprint-friendly wrapper)
	 * @return Current user ID or empty string
	 */
	UFUNCTION(BlueprintPure, Category = "DegenHF|Authentication")
	static FString GetCurrentUserId();

	/**
	 * Get current username (Blueprint-friendly wrapper)
	 * @return Current username or empty string
	 */
	UFUNCTION(BlueprintPure, Category = "DegenHF|Authentication")
	static FString GetCurrentUsername();

	/**
	 * Logout current user (Blueprint-friendly wrapper)
	 */
	UFUNCTION(BlueprintCallable, Category = "DegenHF|Authentication")
	static void Logout();

private:
	/** Global auth handler instance */
	static class UECCAuthHandler* GlobalAuthHandler;
};