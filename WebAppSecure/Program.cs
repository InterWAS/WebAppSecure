using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using WebAppSecure.Auth;
using WebAppSecure.Models;

var builder = WebApplication.CreateBuilder(args);
const string RequestIdHeader = "X-Request-ID";

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? "Data Source=app.db";
var jwtSection = builder.Configuration.GetSection(JwtOptions.SectionName);

var environmentSigningKey = Environment.GetEnvironmentVariable("JWT_SIGNING_KEY");
var configuredSigningKey = jwtSection["SigningKey"];
var effectiveSigningKey = !string.IsNullOrWhiteSpace(environmentSigningKey)
    ? environmentSigningKey
    : configuredSigningKey;

if (string.IsNullOrWhiteSpace(effectiveSigningKey))
{
    if (builder.Environment.IsDevelopment())
    {
        // Development fallback to avoid hardcoded key in appsettings.
        effectiveSigningKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    }
    else
    {
        throw new InvalidOperationException("JWT signing key nao configurada. Defina a variavel de ambiente JWT_SIGNING_KEY.");
    }
}

if (effectiveSigningKey.Length < 32)
{
    throw new InvalidOperationException("JWT_SIGNING_KEY deve ter pelo menos 32 caracteres.");
}

builder.Services.Configure<JwtOptions>(jwtSection);
builder.Services.PostConfigure<JwtOptions>(options => options.SigningKey = effectiveSigningKey);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(connectionString));

builder.Services
    .AddIdentityCore<IdentityUser>(options =>
    {
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequiredLength = 8;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        options.Lockout.AllowedForNewUsers = true;
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

var jwtOptions = jwtSection.Get<JwtOptions>() ?? new JwtOptions();
jwtOptions.SigningKey = effectiveSigningKey;
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SigningKey));

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidAudience = jwtOptions.Audience,
            IssuerSigningKey = key,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminPolicy", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserOrAdminPolicy", policy => policy.RequireRole("User", "Admin"));
    options.AddPolicy("GuestPolicy", policy => policy.RequireRole("Guest"));
});

builder.Services.AddScoped<IJwtTokenService, JwtTokenService>();

builder.Services.AddHttpsRedirection(options =>
{
    options.RedirectStatusCode = StatusCodes.Status308PermanentRedirect;
});

// Add services to the container.
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new RequireHttpsAttribute());
});

var app = builder.Build();
var securityLogger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("SecurityAudit");

await RoleSeeder.SeedRolesAsync(app.Services);

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}

app.UseHsts();

app.UseHttpsRedirection();
app.UseRouting();

app.Use(async (context, next) =>
{
    var incomingRequestId = context.Request.Headers[RequestIdHeader].FirstOrDefault();
    var requestId = string.IsNullOrWhiteSpace(incomingRequestId)
        ? Guid.NewGuid().ToString("N")
        : incomingRequestId.Trim();

    context.TraceIdentifier = requestId;
    context.Response.Headers[RequestIdHeader] = requestId;

    var requestLogger = context.RequestServices.GetRequiredService<ILoggerFactory>()
        .CreateLogger("RequestCorrelation");

    using (requestLogger.BeginScope(new Dictionary<string, object>
    {
        ["RequestId"] = requestId
    }))
    {
        await next();
    }
});

app.UseAuthentication();
app.UseAuthorization();

app.Use(async (context, next) =>
{
    await next();

    var path = context.Request.Path.Value ?? string.Empty;
    var isAuthEventEndpoint = path.StartsWith("/api/auth/login", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/api/auth/refresh", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/api/auth/revoke", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/submit", StringComparison.OrdinalIgnoreCase);
    var isProtectedApi = path.StartsWith("/api/secure", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/api/admin", StringComparison.OrdinalIgnoreCase);

    if (!isAuthEventEndpoint && !isProtectedApi)
    {
        return;
    }

    securityLogger.LogInformation(
        "AccessEvent Method={Method} Path={Path} Status={Status} User={User} Authenticated={Authenticated} IP={IP}",
        context.Request.Method,
        path,
        context.Response.StatusCode,
        context.User.Identity?.Name ?? "anonymous",
        context.User.Identity?.IsAuthenticated ?? false,
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
});

app.MapStaticAssets();
app.MapControllers();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();


app.Run();
