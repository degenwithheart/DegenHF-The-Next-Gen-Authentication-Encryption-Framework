#include "ECCAuthBlueprintLibrary.h"
#include "ECCAuthHandler.h"

class UECCAuthHandler* UECCAuthBlueprintLibrary::GlobalAuthHandler = nullptr;

class UECCAuthHandler* UECCAuthBlueprintLibrary::GetECCAuthHandler()
{
	if (GlobalAuthHandler == nullptr)
	{
		GlobalAuthHandler = NewObject<UECCAuthHandler>();
		GlobalAuthHandler->Initialize();
	}
	return GlobalAuthHandler;
}

void UECCAuthBlueprintLibrary::RegisterUser(const FString& Username, const FString& Password, FString& UserId, bool& Success)
{
	UECCAuthHandler* AuthHandler = GetECCAuthHandler();
	if (AuthHandler)
	{
		Success = AuthHandler->RegisterUser(Username, Password, UserId);
	}
	else
	{
		Success = false;
		UserId = TEXT("");
	}
}

void UECCAuthBlueprintLibrary::AuthenticateUser(const FString& Username, const FString& Password, FString& Token, bool& Success)
{
	UECCAuthHandler* AuthHandler = GetECCAuthHandler();
	if (AuthHandler)
	{
		Success = AuthHandler->AuthenticateUser(Username, Password, Token);
	}
	else
	{
		Success = false;
		Token = TEXT("");
	}
}

void UECCAuthBlueprintLibrary::VerifyToken(const FString& Token, FString& UserId, FString& Username, bool& IsValid)
{
	UECCAuthHandler* AuthHandler = GetECCAuthHandler();
	if (AuthHandler)
	{
		IsValid = AuthHandler->VerifyToken(Token, UserId, Username);
	}
	else
	{
		IsValid = false;
		UserId = TEXT("");
		Username = TEXT("");
	}
}

bool UECCAuthBlueprintLibrary::IsUserLoggedIn()
{
	UECCAuthHandler* AuthHandler = GetECCAuthHandler();
	return AuthHandler ? AuthHandler->IsUserLoggedIn() : false;
}

FString UECCAuthBlueprintLibrary::GetCurrentUserId()
{
	UECCAuthHandler* AuthHandler = GetECCAuthHandler();
	return AuthHandler ? AuthHandler->GetCurrentUserId() : TEXT("");
}

FString UECCAuthBlueprintLibrary::GetCurrentUsername()
{
	UECCAuthHandler* AuthHandler = GetECCAuthHandler();
	return AuthHandler ? AuthHandler->GetCurrentUsername() : TEXT("");
}

void UECCAuthBlueprintLibrary::Logout()
{
	UECCAuthHandler* AuthHandler = GetECCAuthHandler();
	if (AuthHandler)
	{
		AuthHandler->Logout();
	}
}