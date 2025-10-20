using System;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace DegenHF.NET_MAUI;

/// <summary>
/// Main .NET MAUI application for ECC-based authentication
/// </summary>
public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder
            .UseMauiApp<App>()
            .ConfigureFonts(fonts =>
            {
                fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
            });

        // Add services
        builder.Services.AddSingleton<EccAuthHandler>();
        builder.Services.AddMemoryCache();
        builder.Services.AddLogging();

        return builder.Build();
    }
}

/// <summary>
/// MAUI App class
/// </summary>
public partial class App : Application
{
    public App()
    {
        InitializeComponent();

        MainPage = new MainPage();
    }
}

/// <summary>
/// Simple API server for demonstration
/// </summary>
public class ApiServer
{
    private readonly EccAuthHandler _authHandler;
    private readonly ILogger<ApiServer> _logger;

    public ApiServer(EccAuthHandler authHandler, ILogger<ApiServer> logger)
    {
        _authHandler = authHandler;
        _logger = logger;
    }

    public async Task StartAsync(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container
        builder.Services.AddSingleton(_authHandler);
        builder.Services.AddLogging();

        var app = builder.Build();

        // Configure the HTTP request pipeline
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseHttpsRedirection();

        // Health check
        app.MapGet("/health", () => new
        {
            status = "healthy",
            service = "degenhf-net-maui",
            timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        });

        // API routes
        var api = app.MapGroup("/api/auth");

        // Register endpoint
        api.MapPost("/register", async (HttpContext context) =>
        {
            try
            {
                var request = await context.Request.ReadFromJsonAsync<RegisterRequest>();
                if (request == null || string.IsNullOrWhiteSpace(request.Username) || request.Password.Length < 8)
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsJsonAsync(new
                    {
                        error = "Invalid input",
                        message = "Username must not be empty and password must be at least 8 characters"
                    });
                    return;
                }

                var userId = _authHandler.Register(request.Username, request.Password);
                context.Response.StatusCode = StatusCodes.Status201Created;
                await context.Response.WriteAsJsonAsync(new
                {
                    user_id = userId,
                    message = "User registered successfully"
                });

                _logger.LogInformation("User registered: {Username}", request.Username);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Registration failed");
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsJsonAsync(new
                {
                    error = "Registration failed",
                    message = ex.Message
                });
            }
        });

        // Login endpoint
        api.MapPost("/login", async (HttpContext context) =>
        {
            try
            {
                var request = await context.Request.ReadFromJsonAsync<LoginRequest>();
                if (request == null || string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsJsonAsync(new
                    {
                        error = "Invalid input",
                        message = "Username and password are required"
                    });
                    return;
                }

                var token = _authHandler.Authenticate(request.Username, request.Password);
                await context.Response.WriteAsJsonAsync(new
                {
                    token = token,
                    message = "Login successful"
                });

                _logger.LogInformation("User logged in: {Username}", request.Username);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login failed");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new
                {
                    error = "Authentication failed",
                    message = ex.Message
                });
            }
        });

        // Verify token endpoint
        api.MapGet("/verify", async (HttpContext context) =>
        {
            try
            {
                var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsJsonAsync(new
                    {
                        error = "Missing token",
                        message = "Authorization header with Bearer token required"
                    });
                    return;
                }

                var token = authHeader.Substring("Bearer ".Length);
                var session = _authHandler.VerifyToken(token);

                await context.Response.WriteAsJsonAsync(new
                {
                    user_id = session.UserId,
                    username = session.Username,
                    message = "Token is valid"
                });

                _logger.LogDebug("Token verified for user: {Username}", session.Username);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token verification failed");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new
                {
                    error = "Token verification failed",
                    message = ex.Message
                });
            }
        });

        // Get user profile
        api.MapGet("/profile", async (HttpContext context) =>
        {
            try
            {
                var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsJsonAsync(new
                    {
                        error = "Missing token",
                        message = "Authorization header with Bearer token required"
                    });
                    return;
                }

                var token = authHeader.Substring("Bearer ".Length);
                var session = _authHandler.VerifyToken(token);
                var profile = _authHandler.GetUserProfile(session.UserId);

                await context.Response.WriteAsJsonAsync(new
                {
                    user_id = profile.UserId,
                    username = profile.Username,
                    profile = new
                    {
                        created_at = profile.CreatedAt.ToString("O"),
                        last_login = profile.LastLogin.ToString("O")
                    }
                });

                _logger.LogDebug("Profile retrieved for user: {Username}", profile.Username);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Profile retrieval failed");
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await context.Response.WriteAsJsonAsync(new
                {
                    error = "Profile retrieval failed",
                    message = ex.Message
                });
            }
        });

        _logger.LogInformation("DegenHF .NET MAUI server starting on https://localhost:5001");
        await app.RunAsync("https://localhost:5001");
    }
}

/// <summary>
/// Request/Response models
/// </summary>
public class RegisterRequest
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
}

public class LoginRequest
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
}

/// <summary>
/// Program entry point
/// </summary>
public class Program
{
    public static async Task Main(string[] args)
    {
        // Check if we should run as API server
        if (args.Contains("--api-server"))
        {
            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddSingleton<EccAuthHandler>();
            builder.Services.AddMemoryCache();
            builder.Services.AddLogging();

            var app = builder.Services.BuildServiceProvider().GetRequiredService<ApiServer>();
            await app.StartAsync(args);
        }
        else
        {
            // Run MAUI app
            var app = MauiProgram.CreateMauiApp();
            await app.RunAsync(args);
        }
    }
}