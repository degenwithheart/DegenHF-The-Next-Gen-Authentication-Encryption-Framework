#include "DegenHF.h"
#include "ECCAuthHandler.h"
#include "Modules/ModuleManager.h"

#define LOCTEXT_NAMESPACE "FDegenHFModule"

void FDegenHFModule::StartupModule()
{
	// This code will execute after your module is loaded into memory
	// (but after global variables are initialized, of course.)
	UE_LOG(LogTemp, Log, TEXT("DegenHF module started"));
}

void FDegenHFModule::ShutdownModule()
{
	// This function may be called during shutdown to clean up your module
	// For modules that support dynamic reloading, we call this function
	// before unloading the module.
	UE_LOG(LogTemp, Log, TEXT("DegenHF module shutdown"));
}

#undef LOCTEXT_NAMESPACE

IMPLEMENT_MODULE(FDegenHFModule, DegenHF)