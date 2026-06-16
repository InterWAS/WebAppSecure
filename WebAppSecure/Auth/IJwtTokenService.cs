namespace WebAppSecure.Auth;

using Microsoft.AspNetCore.Identity;

public interface IJwtTokenService
{
    Task<string> GenerateTokenAsync(IdentityUser user);
}
