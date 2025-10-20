# Sample C++ Authentication Integration

This guide shows how to integrate DegenHF ECC authentication into your Unreal Engine C++ game.

## GameInstance Integration

Create or modify your GameInstance class to include authentication:

```cpp
// In your GameInstance header (.h)
#include "ECCAuthHandler.h"

class UMyGameInstance : public UGameInstance
{
    GENERATED_BODY()

public:
    virtual void Init() override;
    virtual void Shutdown() override;

    // Authentication functions
    void RegisterPlayer(const FString& Username, const FString& Password);
    void LoginPlayer(const FString& Username, const FString& Password);
    void LogoutPlayer();
    bool IsPlayerLoggedIn() const;

private:
    UPROPERTY()
    UECCAuthHandler* AuthHandler;

    FString CurrentPlayerId;
    FString CurrentPlayerName;
};
```

```cpp
// In your GameInstance implementation (.cpp)
void UMyGameInstance::Init()
{
    Super::Init();

    // Initialize authentication handler
    AuthHandler = NewObject<UECCAuthHandler>(this);
    AuthHandler->Initialize();

    // Load saved session
    AuthHandler->LoadAuthData();
}

void UMyGameInstance::Shutdown()
{
    // Save authentication data
    if (AuthHandler)
    {
        AuthHandler->SaveAuthData();
    }

    Super::Shutdown();
}

void UMyGameInstance::RegisterPlayer(const FString& Username, const FString& Password)
{
    if (!AuthHandler) return;

    FString UserId;
    if (AuthHandler->RegisterUser(Username, Password, UserId))
    {
        UE_LOG(LogTemp, Log, TEXT("Player registered: %s (ID: %s)"), *Username, *UserId);
        // Show success UI
    }
    else
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to register player: %s"), *Username);
        // Show error UI
    }
}

void UMyGameInstance::LoginPlayer(const FString& Username, const FString& Password)
{
    if (!AuthHandler) return;

    FString Token;
    if (AuthHandler->AuthenticateUser(Username, Password, Token))
    {
        CurrentPlayerId = AuthHandler->GetCurrentUserId();
        CurrentPlayerName = AuthHandler->GetCurrentUsername();

        UE_LOG(LogTemp, Log, TEXT("Player logged in: %s"), *CurrentPlayerName);
        // Transition to main menu
    }
    else
    {
        UE_LOG(LogTemp, Warning, TEXT("Login failed for: %s"), *Username);
        // Show login error
    }
}

void UMyGameInstance::LogoutPlayer()
{
    if (AuthHandler)
    {
        AuthHandler->Logout();
    }

    CurrentPlayerId.Empty();
    CurrentPlayerName.Empty();

    UE_LOG(LogTemp, Log, TEXT("Player logged out"));
    // Return to login screen
}

bool UMyGameInstance::IsPlayerLoggedIn() const
{
    return AuthHandler && AuthHandler->IsUserLoggedIn();
}
```

## PlayerController Integration

Add authentication checks to your PlayerController:

```cpp
// In PlayerController
void AMyPlayerController::BeginPlay()
{
    Super::BeginPlay();

    // Check if player is authenticated
    UMyGameInstance* GameInstance = Cast<UMyGameInstance>(GetGameInstance());
    if (GameInstance && !GameInstance->IsPlayerLoggedIn())
    {
        // Show login screen or redirect
        ShowLoginScreen();
    }
}

void AMyPlayerController::ShowLoginScreen()
{
    // Create and show login widget
    if (LoginWidgetClass)
    {
        LoginWidget = CreateWidget<UUserWidget>(this, LoginWidgetClass);
        if (LoginWidget)
        {
            LoginWidget->AddToViewport();
        }
    }
}
```

## Multiplayer Authentication

For multiplayer games, validate tokens on the server:

```cpp
// In GameMode
void AMyGameMode::PreLogin(const FString& Options, const FString& Address,
                          const FUniqueNetIdRepl& UniqueId, FString& ErrorMessage)
{
    Super::PreLogin(Options, Address, UniqueId, ErrorMessage);

    // Extract token from options
    FString Token;
    if (Options.Contains(TEXT("Token=")))
    {
        Token = UGameplayStatics::ParseOption(Options, TEXT("Token"));
    }

    // Validate token
    FString UserId, Username;
    if (!ValidatePlayerToken(Token, UserId, Username))
    {
        ErrorMessage = TEXT("Invalid authentication token");
        return;
    }

    // Store validated player info
    PendingPlayers.Add(UniqueId, FPlayerAuthInfo(UserId, Username));
}

bool AMyGameMode::ValidatePlayerToken(const FString& Token, FString& OutUserId, FString& OutUsername)
{
    // Get auth handler from GameInstance
    UMyGameInstance* GameInstance = Cast<UMyGameInstance>(GetGameInstance());
    if (!GameInstance || !GameInstance->GetAuthHandler())
    {
        return false;
    }

    return GameInstance->GetAuthHandler()->VerifyToken(Token, OutUserId, OutUsername);
}
```

## Save Game Integration

Integrate authentication with save games:

```cpp
// When saving game
void AMyPlayerController::SaveGame()
{
    UMyGameInstance* GameInstance = Cast<UMyGameInstance>(GetGameInstance());
    if (GameInstance && GameInstance->IsPlayerLoggedIn())
    {
        FString PlayerId = GameInstance->GetCurrentPlayerId();

        // Include player ID in save data for ownership verification
        SaveData.PlayerId = PlayerId;
        SaveData.AuthToken = GameInstance->GetAuthHandler()->GetCurrentToken();

        UGameplayStatics::SaveGameToSlot(SaveData, SaveSlotName, 0);
    }
}

// When loading game
void AMyPlayerController::LoadGame()
{
    USaveGame* LoadedSave = UGameplayStatics::LoadGameFromSlot(SaveSlotName, 0);
    if (LoadedSave)
    {
        FMySaveData* SaveData = Cast<FMySaveData>(LoadedSave);
        if (SaveData)
        {
            // Verify save ownership
            UMyGameInstance* GameInstance = Cast<UMyGameInstance>(GetGameInstance());
            if (GameInstance && GameInstance->IsPlayerLoggedIn())
            {
                FString CurrentPlayerId = GameInstance->GetCurrentPlayerId();
                if (SaveData->PlayerId == CurrentPlayerId)
                {
                    // Load the save data
                    ApplySaveData(SaveData);
                }
                else
                {
                    UE_LOG(LogTemp, Warning, TEXT("Save file belongs to different player"));
                }
            }
        }
    }
}
```

## Error Handling

Always handle authentication errors gracefully:

```cpp
void UMyGameInstance::HandleAuthError(EAuthError Error)
{
    switch (Error)
    {
    case EAuthError::NetworkError:
        ShowMessage(TEXT("Network connection failed. Please check your internet connection."));
        break;
    case EAuthError::InvalidCredentials:
        ShowMessage(TEXT("Invalid username or password."));
        break;
    case EAuthError::TokenExpired:
        ShowMessage(TEXT("Your session has expired. Please log in again."));
        LogoutPlayer();
        break;
    default:
        ShowMessage(TEXT("An authentication error occurred."));
        break;
    }
}
```

## Performance Optimization

For better performance in large games:

```cpp
// Use async authentication
void UMyGameInstance::LoginPlayerAsync(const FString& Username, const FString& Password)
{
    AsyncTask(ENamedThreads::AnyBackgroundThreadNormalTask, [this, Username, Password]()
    {
        FString Token;
        bool Success = AuthHandler->AuthenticateUser(Username, Password, Token);

        // Switch back to game thread
        AsyncTask(ENamedThreads::GameThread, [this, Success, Token]()
        {
            OnLoginCompleted(Success, Token);
        });
    });
}
```

This C++ integration provides full control over the authentication flow while maintaining the security benefits of ECC cryptography.