namespace WebAppSecure.Controllers;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebAppSecure.Security;

[ApiController]
[Route("api/admin")]
[Authorize(Policy = "AdminPolicy")]
public class AdminController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ILogger<AdminController> _logger;

    public AdminController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, ILogger<AdminController> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _logger = logger;
    }

    [HttpGet("dashboard")]
    public IActionResult Dashboard()
    {
        _logger.LogInformation("Admin access granted: dashboard. User={User} RequestId={RequestId}", User.Identity?.Name ?? "anonymous", HttpContext.TraceIdentifier);
        return Ok(new { message = "Acesso administrativo autorizado." });
    }

    [HttpPost("assign-role")]
    public async Task<IActionResult> AssignRole(string username, string role)
    {
        var sanitizedUsername = InputSanitizer.SanitizeUsername(username);
        var sanitizedRole = role?.Trim() ?? string.Empty;

        if (string.IsNullOrWhiteSpace(sanitizedUsername) || !InputSanitizer.IsValidRoleName(sanitizedRole))
        {
            _logger.LogWarning("Admin assign-role denied: invalid input. TargetUsername={TargetUsername} Role={Role} RequestedBy={RequestedBy} RequestId={RequestId}", sanitizedUsername, sanitizedRole, User.Identity?.Name ?? "anonymous", HttpContext.TraceIdentifier);
            return BadRequest(new { message = "Parametros invalidos para atribuicao de role." });
        }

        if (!await _roleManager.RoleExistsAsync(sanitizedRole))
        {
            _logger.LogWarning("Admin assign-role denied: role does not exist. Role={Role} RequestedBy={RequestedBy} RequestId={RequestId}", sanitizedRole, User.Identity?.Name ?? "anonymous", HttpContext.TraceIdentifier);
            return BadRequest(new { message = "Role inexistente." });
        }

        var user = await _userManager.FindByNameAsync(sanitizedUsername);
        if (user is null)
        {
            _logger.LogWarning("Admin assign-role failed: target user not found. TargetUsername={TargetUsername} RequestedBy={RequestedBy} RequestId={RequestId}", sanitizedUsername, User.Identity?.Name ?? "anonymous", HttpContext.TraceIdentifier);
            return NotFound(new { message = "Usuario nao encontrado." });
        }

        var result = await _userManager.AddToRoleAsync(user, sanitizedRole);
        if (!result.Succeeded)
        {
            _logger.LogWarning("Admin assign-role failed. TargetUsername={TargetUsername} Role={Role} RequestedBy={RequestedBy} RequestId={RequestId} Errors={Errors}", sanitizedUsername, sanitizedRole, User.Identity?.Name ?? "anonymous", HttpContext.TraceIdentifier, string.Join(" | ", result.Errors.Select(e => e.Description)));
            return BadRequest(new { message = "Falha ao atribuir role.", errors = result.Errors.Select(e => e.Description) });
        }

        _logger.LogInformation("Admin assign-role success. TargetUsername={TargetUsername} Role={Role} RequestedBy={RequestedBy} RequestId={RequestId}", sanitizedUsername, sanitizedRole, User.Identity?.Name ?? "anonymous", HttpContext.TraceIdentifier);

        return Ok(new { message = "Role atribuida com sucesso." });
    }
}
