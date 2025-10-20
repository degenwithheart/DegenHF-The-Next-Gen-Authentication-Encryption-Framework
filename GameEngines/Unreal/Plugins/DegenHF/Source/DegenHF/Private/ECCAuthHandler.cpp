#include "ECCAuthHandler.h"
#include "Misc/SecureHash.h"
#include "Misc/Base64.h"
#include "Serialization/JsonReader.h"
#include "Serialization/JsonSerializer.h"
#include "HAL/FileManager.h"
#include "Misc/Paths.h"
#include "Misc/ConfigCacheIni.h"
#include "GenericPlatform/GenericPlatformCrypto.h"

UECCAuthHandler::UECCAuthHandler()
	: HashIterations(10000)
	, TokenExpiryHours(24.0f)
	, CacheExpiryMinutes(5.0f)
{
}

void UECCAuthHandler::Initialize()
{
	// Generate ECC key pair
	if (!GenerateECCKeyPair())
	{
		UE_LOG(LogTemp, Error, TEXT("Failed to generate ECC key pair"));
		return;
	}

	// Load saved authentication data
	LoadAuthData();

	UE_LOG(LogTemp, Log, TEXT("DegenHF ECC Authentication initialized"));
}

bool UECCAuthHandler::RegisterUser(const FString& Username, const FString& Password, FString& OutUserId)
{
	if (Username.IsEmpty() || Password.IsEmpty())
	{
		UE_LOG(LogTemp, Warning, TEXT("Username and password cannot be empty"));
		return false;
	}

	// Generate user ID
	OutUserId = GenerateUserId();

	// Hash password
	TArray<uint8> Salt;
	TArray<uint8> Hash;
	if (!HashPassword(Password, Salt, Hash))
	{
		UE_LOG(LogTemp, Error, TEXT("Failed to hash password"));
		return false;
	}

	// Store user data (in a real implementation, this would go to a database)
	// For demo purposes, we'll use PlayerPrefs-like storage
	FString UserData = FString::Printf(TEXT("%s|%s|%s"),
		*Username,
		*FBase64::Encode(Salt),
		*FBase64::Encode(Hash));

	FString SavePath = FPaths::ProjectSavedDir() / TEXT("DegenHF") / TEXT("Users") / OutUserId + TEXT(".dat");
	if (!FFileHelper::SaveStringToFile(UserData, *SavePath))
	{
		UE_LOG(LogTemp, Error, TEXT("Failed to save user data"));
		return false;
	}

	UE_LOG(LogTemp, Log, TEXT("User registered: %s (ID: %s)"), *Username, *OutUserId);
	return true;
}

bool UECCAuthHandler::AuthenticateUser(const FString& Username, const FString& Password, FString& OutToken)
{
	if (Username.IsEmpty() || Password.IsEmpty())
	{
		return false;
	}

	// Find user data (in real implementation, query database)
	FString UserId;
	TArray<uint8> StoredSalt;
	TArray<uint8> StoredHash;

	if (!LoadUserData(Username, UserId, StoredSalt, StoredHash))
	{
		UE_LOG(LogTemp, Warning, TEXT("User not found: %s"), *Username);
		return false;
	}

	// Verify password
	if (!VerifyPassword(Password, StoredSalt, StoredHash))
	{
		UE_LOG(LogTemp, Warning, TEXT("Invalid password for user: %s"), *Username);
		return false;
	}

	// Generate token
	OutToken = GenerateToken(UserId, Username);

	// Cache token
	TokenCache.Add(OutToken, UserId);

	// Set current user
	CurrentUserId = UserId;
	CurrentUsername = Username;
	CurrentToken = OutToken;

	// Save session
	SaveAuthData();

	UE_LOG(LogTemp, Log, TEXT("User authenticated: %s"), *Username);
	return true;
}

bool UECCAuthHandler::VerifyToken(const FString& Token, FString& OutUserId, FString& OutUsername)
{
	// Check cache first
	if (TokenCache.Contains(Token))
	{
		OutUserId = TokenCache[Token];
		// In real implementation, get username from user data
		OutUsername = TEXT("User"); // Placeholder
		return true;
	}

	// Simple token validation (in production, use proper JWT)
	if (ValidateToken(Token, OutUserId, OutUsername))
	{
		TokenCache.Add(Token, OutUserId);
		return true;
	}

	return false;
}

bool UECCAuthHandler::CreateSession(const FString& UserId, FString& OutSessionId)
{
	OutSessionId = GenerateSessionId();
	SessionCache.Add(OutSessionId, UserId);
	return true;
}

bool UECCAuthHandler::GetSession(const FString& SessionId, FString& OutUserId, FString& OutUsername)
{
	if (SessionCache.Contains(SessionId))
	{
		OutUserId = SessionCache[SessionId];
		OutUsername = TEXT("User"); // Placeholder
		return true;
	}
	return false;
}

bool UECCAuthHandler::IsUserLoggedIn() const
{
	return !CurrentUserId.IsEmpty() && !CurrentToken.IsEmpty();
}

FString UECCAuthHandler::GetCurrentUserId() const
{
	return CurrentUserId;
}

FString UECCAuthHandler::GetCurrentUsername() const
{
	return CurrentUsername;
}

void UECCAuthHandler::Logout()
{
	CurrentUserId.Empty();
	CurrentUsername.Empty();
	CurrentToken.Empty();
	TokenCache.Empty();
	SessionCache.Empty();

	// Clear saved data
	FString SavePath = FPaths::ProjectSavedDir() / TEXT("DegenHF") / TEXT("Session.dat");
	IFileManager::Get().Delete(*SavePath);

	UE_LOG(LogTemp, Log, TEXT("User logged out"));
}

void UECCAuthHandler::SaveAuthData()
{
	if (CurrentUserId.IsEmpty())
		return;

	FString SessionData = FString::Printf(TEXT("%s|%s|%s"),
		*CurrentUserId,
		*CurrentUsername,
		*CurrentToken);

	FString SavePath = FPaths::ProjectSavedDir() / TEXT("DegenHF") / TEXT("Session.dat");
	FFileHelper::SaveStringToFile(SessionData, *SavePath);
}

void UECCAuthHandler::LoadAuthData()
{
	FString SavePath = FPaths::ProjectSavedDir() / TEXT("DegenHF") / TEXT("Session.dat");
	FString SessionData;

	if (FFileHelper::LoadFileToString(SessionData, *SavePath))
	{
		TArray<FString> Parts;
		SessionData.ParseIntoArray(Parts, TEXT("|"), true);

		if (Parts.Num() >= 3)
		{
			CurrentUserId = Parts[0];
			CurrentUsername = Parts[1];
			CurrentToken = Parts[2];
		}
	}
}

bool UECCAuthHandler::HashPassword(const FString& Password, TArray<uint8>& OutSalt, TArray<uint8>& OutHash)
{
	// Generate random salt
	OutSalt.SetNum(32);
	FGenericPlatformCrypto::GetRandomBytes(OutSalt.GetData(), OutSalt.Num());

	// Convert password to UTF-8
	FTCHARToUTF8 PasswordUTF8(*Password);
	const uint8* PasswordData = (const uint8*)PasswordUTF8.Get();

	// Combine password and salt
	TArray<uint8> Combined;
	Combined.Append(PasswordData, Password.Len());
	Combined.Append(OutSalt);

	// Hash multiple times for security
	OutHash = Combined;
	for (int32 i = 0; i < HashIterations; ++i)
	{
		FSHA256::HashBuffer(OutHash.GetData(), OutHash.Num(), OutHash.GetData());
	}

	return true;
}

bool UECCAuthHandler::VerifyPassword(const FString& Password, const TArray<uint8>& Salt, const TArray<uint8>& Hash)
{
	TArray<uint8> ComputedSalt = Salt;
	TArray<uint8> ComputedHash;

	if (!HashPassword(Password, ComputedSalt, ComputedHash))
	{
		return false;
	}

	// Constant-time comparison to prevent timing attacks
	return FGenericPlatformCrypto::ConstantTimeCompare(ComputedHash, Hash);
}

FString UECCAuthHandler::GenerateToken(const FString& UserId, const FString& Username)
{
	// Simple token generation (in production, use proper JWT)
	int64 Timestamp = GetCurrentTimestamp();
	FString TokenData = FString::Printf(TEXT("%s|%s|%lld"), *UserId, *Username, Timestamp);

	// Create a simple hash-based token
	FSHA256::HashBuffer(TCHAR_TO_UTF8(*TokenData), TokenData.Len(), TokenData);
	return FBase64::Encode(TokenData);
}

bool UECCAuthHandler::ValidateToken(const FString& Token, FString& OutUserId, FString& OutUsername)
{
	// Simple token validation (in production, use proper JWT verification)
	// This is a placeholder - real implementation would verify signature
	OutUserId = TEXT("user_123"); // Placeholder
	OutUsername = TEXT("User"); // Placeholder
	return true;
}

FString UECCAuthHandler::GenerateSimpleToken(const FString& UserId, const FString& Username)
{
	return GenerateToken(UserId, Username);
}

bool UECCAuthHandler::GenerateECCKeyPair()
{
	// Generate ECC key pair (simplified for UE compatibility)
	// In a real implementation, this would use proper ECC key generation
	PrivateKey.SetNum(32);
	PublicKey.SetNum(64);

	FGenericPlatformCrypto::GetRandomBytes(PrivateKey.GetData(), PrivateKey.Num());
	FGenericPlatformCrypto::GetRandomBytes(PublicKey.GetData(), PublicKey.Num());

	return true;
}

bool UECCAuthHandler::SignData(const TArray<uint8>& Data, TArray<uint8>& OutSignature)
{
	// Simplified signing (in production, use proper ECC signing)
	OutSignature.SetNum(64);
	FGenericPlatformCrypto::GetRandomBytes(OutSignature.GetData(), OutSignature.Num());
	return true;
}

bool UECCAuthHandler::VerifySignature(const TArray<uint8>& Data, const TArray<uint8>& Signature)
{
	// Simplified verification (in production, use proper ECC verification)
	return true;
}

FString UECCAuthHandler::GenerateUserId()
{
	return FString::Printf(TEXT("user_%lld"), GetCurrentTimestamp());
}

FString UECCAuthHandler::GenerateSessionId()
{
	return FString::Printf(TEXT("session_%lld"), GetCurrentTimestamp());
}

int64 UECCAuthHandler::GetCurrentTimestamp()
{
	return FDateTime::UtcNow().ToUnixTimestamp();
}

bool UECCAuthHandler::IsTokenExpired(int64 TokenTimestamp, float ExpiryHours)
{
	int64 CurrentTime = GetCurrentTimestamp();
	int64 ExpiryTime = TokenTimestamp + (int64)(ExpiryHours * 3600.0f);
	return CurrentTime > ExpiryTime;
}

bool UECCAuthHandler::LoadUserData(const FString& Username, FString& OutUserId, TArray<uint8>& OutSalt, TArray<uint8>& OutHash)
{
	// Find user file by scanning directory (inefficient but works for demo)
	FString UsersDir = FPaths::ProjectSavedDir() / TEXT("DegenHF") / TEXT("Users");
	TArray<FString> UserFiles;
	IFileManager::Get().FindFiles(UserFiles, *(UsersDir / TEXT("*.dat")), true, false);

	for (const FString& UserFile : UserFiles)
	{
		FString UserData;
		if (FFileHelper::LoadFileToString(UserData, *(UsersDir / UserFile)))
		{
			TArray<FString> Parts;
			UserData.ParseIntoArray(Parts, TEXT("|"), true);

			if (Parts.Num() >= 3 && Parts[0] == Username)
			{
				OutUserId = FPaths::GetBaseFilename(UserFile);
				FBase64::Decode(Parts[1], OutSalt);
				FBase64::Decode(Parts[2], OutHash);
				return true;
			}
		}
	}

	return false;
}