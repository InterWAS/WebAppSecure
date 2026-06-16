namespace WebAppSecure.Controllers;

using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WebAppSecure.Auth;
using WebAppSecure.Models;
using WebAppSecure.Security;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private const int RefreshTokenExpirationDays = 7;

    private readonly ApplicationDbContext _dbContext;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        ApplicationDbContext dbContext,
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IJwtTokenService jwtTokenService,
        ILogger<AuthController> logger)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _signInManager = signInManager;
        _jwtTokenService = jwtTokenService;
        _logger = logger;
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register(RegisterRequest request)
    {
        var username = InputSanitizer.SanitizeUsername(request.Username);
        var email = InputSanitizer.SanitizeEmail(request.Email);
        var password = request.Password;

        if (string.IsNullOrWhiteSpace(username))
        {
            _logger.LogWarning("Register denied: invalid sanitized username. RequestId={RequestId} IP={IP}", HttpContext.TraceIdentifier, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            return BadRequest(new { message = "Username invalido." });
        }

        if (!InputSanitizer.IsSafeEmail(email))
        {
            _logger.LogWarning("Register denied: invalid email for Username={Username}. RequestId={RequestId} IP={IP}", username, HttpContext.TraceIdentifier, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            return BadRequest(new { message = "Email invalido." });
        }

        if (!InputSanitizer.IsValidPasswordInput(password))
        {
            _logger.LogWarning("Register denied: invalid password payload for Username={Username}. RequestId={RequestId} IP={IP}", username, HttpContext.TraceIdentifier, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            return BadRequest(new { message = "Senha invalida." });
        }

        if (password.Length < 8)
        {
            _logger.LogWarning("Register denied: weak password for Username={Username}. RequestId={RequestId} IP={IP}", username, HttpContext.TraceIdentifier, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            return BadRequest(new { message = "Senha deve ter ao menos 8 caracteres." });
        }

        var user = new IdentityUser
        {
            UserName = username,
            Email = email,
            EmailConfirmed = false
        };

        var result = await _userManager.CreateAsync(user, password);
        if (!result.Succeeded)
        {
            _logger.LogWarning("Register failed for Username={Username}. RequestId={RequestId} Errors={Errors}", username, HttpContext.TraceIdentifier, string.Join(" | ", result.Errors.Select(e => e.Description)));
            return BadRequest(new { message = "Falha no cadastro.", errors = result.Errors.Select(e => e.Description) });
        }

        await _userManager.AddToRoleAsync(user, "User");

        var tokenResponse = await IssueTokenPairAsync(user);
        _logger.LogInformation("Register success for Username={Username}. UserId={UserId} RequestId={RequestId}", username, user.Id, HttpContext.TraceIdentifier);
        return Ok(new { message = "Usuario registrado com sucesso.", tokens = tokenResponse });
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login(LoginRequest request)
    {
        var username = InputSanitizer.SanitizeUsername(request.Username);
        var password = request.Password;

        if (string.IsNullOrWhiteSpace(username) || !InputSanitizer.IsValidPasswordInput(password))
        {
            _logger.LogWarning("Login denied: invalid credentials payload. RequestId={RequestId} IP={IP}", HttpContext.TraceIdentifier, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            return BadRequest(new { message = "Credenciais invalidas." });
        }

        var user = await _userManager.FindByNameAsync(username);
        if (user is null)
        {
            _logger.LogWarning("Login failed: user not found. Username={Username} RequestId={RequestId}", username, HttpContext.TraceIdentifier);
            return Unauthorized(new { message = "Usuario ou senha invalidos." });
        }

        var signInResult = await _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);
        if (signInResult.IsLockedOut)
        {
            _logger.LogWarning("Login blocked: account locked. Username={Username} UserId={UserId} RequestId={RequestId}", username, user.Id, HttpContext.TraceIdentifier);
            return Unauthorized(new { message = "Usuario temporariamente bloqueado." });
        }

        if (!signInResult.Succeeded)
        {
            _logger.LogWarning("Login failed: invalid password. Username={Username} UserId={UserId} RequestId={RequestId}", username, user.Id, HttpContext.TraceIdentifier);
            return Unauthorized(new { message = "Usuario ou senha invalidos." });
        }

        var tokenResponse = await IssueTokenPairAsync(user);
        _logger.LogInformation("Login success. Username={Username} UserId={UserId} RequestId={RequestId}", username, user.Id, HttpContext.TraceIdentifier);
        return Ok(new { message = "Login OK.", tokens = tokenResponse });
    }

    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<IActionResult> Refresh(RefreshTokenRequest request)
    {
        var refreshToken = request.RefreshToken.Trim();
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            _logger.LogWarning("Refresh denied: empty token. RequestId={RequestId} IP={IP}", HttpContext.TraceIdentifier, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            return BadRequest(new { message = "Refresh token invalido." });
        }

        var refreshTokenHash = ComputeSha256(refreshToken);
        var storedRefreshToken = await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.TokenHash == refreshTokenHash);

        if (storedRefreshToken is null || !storedRefreshToken.IsActive)
        {
            _logger.LogWarning("Refresh failed: invalid or expired token hash. RequestId={RequestId}", HttpContext.TraceIdentifier);
            return Unauthorized(new { message = "Refresh token invalido ou expirado." });
        }

        var user = await _userManager.FindByIdAsync(storedRefreshToken.UserId);
        if (user is null)
        {
            _logger.LogWarning("Refresh failed: user not found for token. UserId={UserId} RequestId={RequestId}", storedRefreshToken.UserId, HttpContext.TraceIdentifier);
            return Unauthorized(new { message = "Usuario invalido para refresh token." });
        }

        storedRefreshToken.RevokedAtUtc = DateTime.UtcNow;

        var tokenResponse = await IssueTokenPairAsync(user, storedRefreshToken.TokenHash);
        await _dbContext.SaveChangesAsync();

        _logger.LogInformation("Refresh success. UserId={UserId} RequestId={RequestId}", user.Id, HttpContext.TraceIdentifier);

        return Ok(new { message = "Token renovado com sucesso.", tokens = tokenResponse });
    }

    [HttpPost("revoke")]
    [AllowAnonymous]
    public async Task<IActionResult> Revoke(RevokeTokenRequest request)
    {
        var refreshToken = request.RefreshToken.Trim();
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            _logger.LogWarning("Revoke denied: empty token. RequestId={RequestId} IP={IP}", HttpContext.TraceIdentifier, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            return BadRequest(new { message = "Refresh token invalido." });
        }

        var refreshTokenHash = ComputeSha256(refreshToken);
        var storedRefreshToken = await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.TokenHash == refreshTokenHash);

        if (storedRefreshToken is null)
        {
            _logger.LogWarning("Revoke failed: token not found. RequestId={RequestId}", HttpContext.TraceIdentifier);
            return NotFound(new { message = "Refresh token nao encontrado." });
        }

        if (!storedRefreshToken.IsActive)
        {
            _logger.LogWarning("Revoke ignored: token already revoked or expired. UserId={UserId} RequestId={RequestId}", storedRefreshToken.UserId, HttpContext.TraceIdentifier);
            return BadRequest(new { message = "Refresh token ja revogado ou expirado." });
        }

        storedRefreshToken.RevokedAtUtc = DateTime.UtcNow;
        await _dbContext.SaveChangesAsync();

        _logger.LogInformation("Revoke success. UserId={UserId} RequestId={RequestId}", storedRefreshToken.UserId, HttpContext.TraceIdentifier);

        return Ok(new { message = "Refresh token revogado com sucesso." });
    }

    private async Task<AuthTokenResponse> IssueTokenPairAsync(IdentityUser user, string? previousTokenHash = null)
    {
        var accessToken = await _jwtTokenService.GenerateTokenAsync(user);
        var refreshToken = GenerateRefreshToken();
        var refreshTokenHash = ComputeSha256(refreshToken);

        var refreshTokenEntity = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = refreshTokenHash,
            CreatedAtUtc = DateTime.UtcNow,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(RefreshTokenExpirationDays),
            ReplacedByTokenHash = null
        };

        _dbContext.RefreshTokens.Add(refreshTokenEntity);

        if (!string.IsNullOrWhiteSpace(previousTokenHash))
        {
            var previous = await _dbContext.RefreshTokens.FirstOrDefaultAsync(rt => rt.TokenHash == previousTokenHash);
            if (previous is not null)
            {
                previous.ReplacedByTokenHash = refreshTokenHash;
            }
        }

        await _dbContext.SaveChangesAsync();

        var roles = await _userManager.GetRolesAsync(user);
        return new AuthTokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            Roles = roles.ToList()
        };
    }

    private static string GenerateRefreshToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        return Convert.ToBase64String(bytes);
    }

    private static string ComputeSha256(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash);
    }
}
