using UnrealBuildTool;

public class DegenHF : ModuleRules
{
	public DegenHF(ReadOnlyTargetRules Target) : base(Target)
	{
		PCHUsage = ModuleRules.PCHUsageMode.UseExplicitOrSharedPCHs;

		PublicDependencyModuleNames.AddRange(
			new string[]
			{
				"Core",
				"CoreUObject",
				"Engine",
				"InputCore"
			}
		);

		PrivateDependencyModuleNames.AddRange(
			new string[]
			{
				"Slate",
				"SlateCore",
				"Json",
				"JsonUtilities",
				"HTTP"
			}
		);

		// Enable C++17 for better cryptography support
		CppStandard = CppStandardVersion.Cpp17;

		// Add preprocessor definitions for ECC support
		PublicDefinitions.Add("WITH_ECC_AUTH=1");

		// Platform-specific optimizations
		if (Target.Platform == UnrealTargetPlatform.Win64)
		{
			PublicDefinitions.Add("PLATFORM_WINDOWS=1");
		}
		else if (Target.Platform == UnrealTargetPlatform.Mac)
		{
			PublicDefinitions.Add("PLATFORM_MAC=1");
		}
		else if (Target.Platform == UnrealTargetPlatform.Linux)
		{
			PublicDefinitions.Add("PLATFORM_LINUX=1");
		}
	}
}