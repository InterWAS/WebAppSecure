namespace WebAppSecure.Test;

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

public class RoleAuthorizationIntegrationTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public RoleAuthorizationIntegrationTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task UserRole_ShouldAccessUserPolicy_AndBeForbiddenFromAdminPolicy()
    {
        await _factory.SeedUserWithRoleAsync("rbac_user", "rbac_user@example.com", "Str0ng!Pass123", "User");
        using var client = _factory.CreateHttpsClient();

        var loginResponse = await client.PostAsJsonAsync("/api/auth/login", new
        {
            username = "rbac_user",
            password = "Str0ng!Pass123"
        });

        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);
        var loginJson = JsonDocument.Parse(await loginResponse.Content.ReadAsStringAsync());
        var accessToken = loginJson.RootElement.GetProperty("tokens").GetProperty("accessToken").GetString();
        Assert.False(string.IsNullOrWhiteSpace(accessToken));

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var userPolicyResponse = await client.GetAsync("/api/secure/user-or-admin");
        Assert.Equal(HttpStatusCode.OK, userPolicyResponse.StatusCode);

        var adminResponse = await client.GetAsync("/api/admin/dashboard");
        Assert.Equal(HttpStatusCode.Forbidden, adminResponse.StatusCode);
    }

    [Fact]
    public async Task AdminRole_ShouldAccessAdminPolicy()
    {
        await _factory.SeedUserWithRoleAsync("rbac_admin", "rbac_admin@example.com", "Str0ng!Pass123", "Admin");
        using var client = _factory.CreateHttpsClient();

        var loginResponse = await client.PostAsJsonAsync("/api/auth/login", new
        {
            username = "rbac_admin",
            password = "Str0ng!Pass123"
        });

        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);
        var loginJson = JsonDocument.Parse(await loginResponse.Content.ReadAsStringAsync());
        var accessToken = loginJson.RootElement.GetProperty("tokens").GetProperty("accessToken").GetString();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var adminResponse = await client.GetAsync("/api/admin/dashboard");
        Assert.Equal(HttpStatusCode.OK, adminResponse.StatusCode);
    }

    [Fact]
    public async Task AnonymousRequest_ToProtectedEndpoint_ShouldReturnUnauthorized()
    {
        using var client = _factory.CreateHttpsClient();
        var response = await client.GetAsync("/api/secure/profile");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
