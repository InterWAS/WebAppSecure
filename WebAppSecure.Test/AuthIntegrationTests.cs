namespace WebAppSecure.Test;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

public class AuthIntegrationTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public AuthIntegrationTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Register_Then_Login_ShouldReturnAccessAndRefreshTokens()
    {
        using var client = _factory.CreateHttpsClient();

        var registerPayload = new
        {
            username = "testuser_auth",
            email = "testuser_auth@example.com",
            password = "Str0ng!Pass123"
        };

        var registerResponse = await client.PostAsJsonAsync("/api/auth/register", registerPayload);
        Assert.Equal(HttpStatusCode.OK, registerResponse.StatusCode);

        var registerJson = JsonDocument.Parse(await registerResponse.Content.ReadAsStringAsync());
        var registerTokens = registerJson.RootElement.GetProperty("tokens");
        Assert.False(string.IsNullOrWhiteSpace(registerTokens.GetProperty("accessToken").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(registerTokens.GetProperty("refreshToken").GetString()));

        var loginPayload = new
        {
            username = "testuser_auth",
            password = "Str0ng!Pass123"
        };

        var loginResponse = await client.PostAsJsonAsync("/api/auth/login", loginPayload);
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);

        var loginJson = JsonDocument.Parse(await loginResponse.Content.ReadAsStringAsync());
        var loginTokens = loginJson.RootElement.GetProperty("tokens");
        Assert.False(string.IsNullOrWhiteSpace(loginTokens.GetProperty("accessToken").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(loginTokens.GetProperty("refreshToken").GetString()));
    }

    [Fact]
    public async Task Login_WithWrongPassword_ShouldReturnUnauthorized()
    {
        await _factory.SeedUserWithRoleAsync("wrongpass_user", "wrongpass_user@example.com", "Str0ng!Pass123", "User");
        using var client = _factory.CreateHttpsClient();

        var loginPayload = new
        {
            username = "wrongpass_user",
            password = "bad-password"
        };

        var loginResponse = await client.PostAsJsonAsync("/api/auth/login", loginPayload);
        Assert.Equal(HttpStatusCode.Unauthorized, loginResponse.StatusCode);
    }
}
