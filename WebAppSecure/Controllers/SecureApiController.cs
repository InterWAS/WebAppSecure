namespace WebAppSecure.Controllers;

using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/secure")]
[Authorize]
public class SecureApiController : ControllerBase
{
    private readonly ILogger<SecureApiController> _logger;

    public SecureApiController(ILogger<SecureApiController> logger)
    {
        _logger = logger;
    }

    [HttpGet("profile")]
    public IActionResult Profile()
    {
        _logger.LogInformation("Protected access: profile endpoint. User={User} RequestId={RequestId}", User.Identity?.Name ?? "anonymous", HttpContext.TraceIdentifier);
        return Ok(new
        {
            username = User.Identity?.Name,
            roles = User.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value)
        });
    }

    [HttpGet("user-or-admin")]
    [Authorize(Policy = "UserOrAdminPolicy")]
    public IActionResult UserOrAdminArea()
    {
        _logger.LogInformation("Protected access: user-or-admin endpoint. User={User} RequestId={RequestId}", User.Identity?.Name ?? "anonymous", HttpContext.TraceIdentifier);
        return Ok(new { message = "Acesso permitido para User ou Admin." });
    }

    [HttpGet("guest")]
    [Authorize(Policy = "GuestPolicy")]
    public IActionResult GuestArea()
    {
        _logger.LogInformation("Protected access: guest endpoint. User={User} RequestId={RequestId}", User.Identity?.Name ?? "anonymous", HttpContext.TraceIdentifier);
        return Ok(new { message = "Acesso permitido para Guest." });
    }
}
