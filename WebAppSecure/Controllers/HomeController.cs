using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WebAppSecure.Models;
using WebAppSecure.Security;

namespace WebAppSecure.Controllers;

public class HomeController : Controller
{
    private readonly ApplicationDbContext _dbContext;
    private readonly ILogger<HomeController> _logger;

    public HomeController(ApplicationDbContext dbContext, ILogger<HomeController> logger)
    {
        _dbContext = dbContext;
        _logger = logger;
    }

    public IActionResult Index()
    {
        return View();
    }

    [HttpGet("/register")]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost("/register")]
    [ValidateAntiForgeryToken]
    public IActionResult Register(string username, string email, string password, string confirmPassword)
    {
        var sanitizedUsername = InputSanitizer.SanitizeUsername(username);
        var sanitizedEmail = InputSanitizer.SanitizeEmail(email);
        var sanitizedPassword = password;
        var sanitizedConfirmPassword = confirmPassword;

        if (string.IsNullOrWhiteSpace(sanitizedUsername))
        {
            ModelState.AddModelError("username", "Username invalido apos sanitizacao.");
        }

        if (!InputSanitizer.IsSafeEmail(sanitizedEmail))
        {
            ModelState.AddModelError("email", "Email invalido.");
        }

        if (!InputSanitizer.IsValidPasswordInput(sanitizedPassword))
        {
            ModelState.AddModelError("password", "Senha invalida apos sanitizacao.");
        }
        else if (sanitizedPassword.Length < 8)
        {
            ModelState.AddModelError("password", "Senha deve ter ao menos 8 caracteres.");
        }

        if (!string.Equals(sanitizedPassword, sanitizedConfirmPassword, StringComparison.Ordinal))
        {
            ModelState.AddModelError("confirmPassword", "Confirmacao de senha nao confere.");
        }

        if (!ModelState.IsValid)
        {
            ViewData["SanitizedUsername"] = sanitizedUsername;
            ViewData["SanitizedEmail"] = sanitizedEmail;
            return View();
        }

        var userAlreadyExists = _dbContext.Users
            .AsNoTracking()
            .Any(u => u.Username == sanitizedUsername || u.Email == sanitizedEmail);

        if (userAlreadyExists)
        {
            ViewData["SanitizedUsername"] = sanitizedUsername;
            ViewData["SanitizedEmail"] = sanitizedEmail;
            ViewData["RegisterError"] = "Usuario ou email ja cadastrado.";
            return View();
        }

        var user = new Users
        {
            Username = sanitizedUsername,
            Email = sanitizedEmail,
            PasswordHash = PasswordHasher.HashPassword(sanitizedPassword)
        };

        _dbContext.Users.Add(user);
        _dbContext.SaveChanges();

        ViewData["RegisterOk"] = "Cadastro realizado com sucesso.";
        return View();
    }

    [HttpPost("/submit")]
    [ValidateAntiForgeryToken]
    public IActionResult Submit(string username, string password)
    {
        var sanitizedUsername = InputSanitizer.SanitizeUsername(username);
        var sanitizedPassword = password;

        if (string.IsNullOrWhiteSpace(sanitizedUsername))
        {
            ModelState.AddModelError("username", "Username invalido apos sanitizacao.");
        }

        if (!InputSanitizer.IsValidPasswordInput(sanitizedPassword))
        {
            ModelState.AddModelError("password", "Senha invalida apos sanitizacao.");
        }

        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Web login denied: invalid model state for Username={Username}", sanitizedUsername);
            ViewData["SanitizedUsername"] = sanitizedUsername;
            return View("Index");
        }

        var user = _dbContext.Users
            .AsNoTracking()
            .FirstOrDefault(u => u.Username == sanitizedUsername);

        if (user is null)
        {
            _logger.LogWarning("Web login failed: user not found. Username={Username}", sanitizedUsername);
            ViewData["SanitizedUsername"] = sanitizedUsername;
            ViewData["LoginError"] = "Usuario nao encontrado.";
            return View("Index");
        }

        if (!PasswordHasher.VerifyPassword(sanitizedPassword, user.PasswordHash))
        {
            _logger.LogWarning("Web login failed: invalid password. Username={Username} UserId={UserId}", sanitizedUsername, user.UserID);
            ViewData["SanitizedUsername"] = sanitizedUsername;
            ViewData["LoginError"] = "Senha incorreta.";
            return View("Index");
        }

        _logger.LogInformation("Web login success. Username={Username} UserId={UserId}", sanitizedUsername, user.UserID);
        ViewData["LoginOk"] = "Login OK.";
        return View("Index");
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
