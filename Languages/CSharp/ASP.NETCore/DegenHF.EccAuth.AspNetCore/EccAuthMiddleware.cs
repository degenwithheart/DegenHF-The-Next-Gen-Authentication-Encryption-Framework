using DegenHF.EccAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;

namespace DegenHF.EccAuth.AspNetCore;

/// <summary>
/// Extension methods for adding ECC authentication to ASP.NET Core
/// </summary>
public static class EccAuthExtensions
{
    /// <summary>
    /// Adds ECC authentication services to the DI container
    /// </summary>
    public static IServiceCollection AddEccAuth(this IServiceCollection services, EccAuthOptions? options = null)
    {
        services.AddSingleton(options ?? new EccAuthOptions());
        services.AddSingleton<EccAuthHandler>();
        return services;
    }

    /// <summary>
    /// Adds ECC authentication middleware to the pipeline
    /// </summary>
    public static IApplicationBuilder UseEccAuth(this IApplicationBuilder app)
    {
        return app.UseMiddleware<EccAuthMiddleware>();
    }
}

/// <summary>
/// ECC authentication middleware for ASP.NET Core
/// </summary>
public class EccAuthMiddleware
{
    private readonly RequestDelegate _next;

    public EccAuthMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var authHandler = context.RequestServices.GetRequiredService<EccAuthHandler>();

        // Check for Authorization header
        if (context.Request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            var headerValue = authHeader.ToString();
            if (headerValue.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                var token = headerValue["Bearer ".Length..].Trim();
                var claims = await authHandler.VerifyTokenAsync(token);

                if (claims != null)
                {
                    context.Items["UserId"] = claims.UserId;
                    context.Items["Username"] = claims.Username;
                }
            }
        }

        await _next(context);
    }
}

/// <summary>
/// Authorization filter for protecting endpoints
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class EccAuthorizeAttribute : Attribute
{
    // This attribute can be used to mark controllers/actions that require authentication
    // The actual authorization logic is handled by the middleware
}