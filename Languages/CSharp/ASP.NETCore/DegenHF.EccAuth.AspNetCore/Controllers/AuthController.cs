using DegenHF.EccAuth;
using Microsoft.AspNetCore.Mvc;

namespace DegenHF.EccAuth.AspNetCore.Controllers;

/// <summary>
/// Authentication controller for ECC-based auth
/// </summary>
[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly EccAuthHandler _authHandler;

    public AuthController(EccAuthHandler authHandler)
    {
        _authHandler = authHandler;
    }

    /// <summary>
    /// Register a new user
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        try
        {
            var userId = await _authHandler.RegisterAsync(request.Username, request.Password);
            return Ok(new
            {
                user_id = userId,
                message = "User registered successfully"
            });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = "Internal server error" });
        }
    }

    /// <summary>
    /// Authenticate user and return token
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        try
        {
            var token = await _authHandler.AuthenticateAsync(request.Username, request.Password);
            return Ok(new
            {
                token = token,
                message = "Login successful"
            });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new { error = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = "Internal server error" });
        }
    }

    /// <summary>
    /// Verify JWT token
    /// </summary>
    [HttpGet("verify")]
    [EccAuthorize]
    public IActionResult Verify()
    {
        var userId = HttpContext.Items["UserId"]?.ToString();
        var username = HttpContext.Items["Username"]?.ToString();

        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(username))
        {
            return Unauthorized(new { error = "User not authenticated" });
        }

        return Ok(new
        {
            user_id = userId,
            username = username,
            message = "Token is valid"
        });
    }

    /// <summary>
    /// Get user profile (protected endpoint)
    /// </summary>
    [HttpGet("profile")]
    [EccAuthorize]
    public IActionResult GetProfile()
    {
        var userId = HttpContext.Items["UserId"]?.ToString();
        var username = HttpContext.Items["Username"]?.ToString();

        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(username))
        {
            return Unauthorized(new { error = "User not authenticated" });
        }

        return Ok(new
        {
            user_id = userId,
            username = username,
            profile = new
            {
                email = "user@example.com", // Mock data
                role = "user",
                created = "2024-01-01"
            }
        });
    }
}

/// <summary>
/// Request model for user registration
/// </summary>
public class RegisterRequest
{
    public required string Username { get; set; }
    public required string Password { get; set; }
}

/// <summary>
/// Request model for user login
/// </summary>
public class LoginRequest
{
    public required string Username { get; set; }
    public required string Password { get; set; }
}