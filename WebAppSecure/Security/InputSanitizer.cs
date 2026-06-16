namespace WebAppSecure.Security;

using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

public static class InputSanitizer
{
    private static readonly Regex UsernameAllowedChars = new("[^a-zA-Z0-9._-]", RegexOptions.Compiled);
    private static readonly Regex PasswordAllowedChars = new(@"[^a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};:,.?/\\|~]", RegexOptions.Compiled);
    private static readonly Regex HtmlLikeTags = new("<.*?>", RegexOptions.Compiled);
    private static readonly EmailAddressAttribute EmailValidator = new();
    private static readonly Regex StrictEmailPattern = new(@"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,10}$", RegexOptions.Compiled);
    private static readonly Regex SuspiciousSqlTerms = new(@"\b(select|insert|update|delete|drop|union|exec|truncate)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex RoleAllowedChars = new("^[a-zA-Z][a-zA-Z0-9_-]{1,49}$", RegexOptions.Compiled);

    public static string SanitizeUsername(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        var value = RemoveControlChars(input.Trim());
        value = HtmlLikeTags.Replace(value, string.Empty);
        value = value.Replace("'", string.Empty)
                     .Replace("\"", string.Empty)
                     .Replace(";", string.Empty)
                     .Replace("--", string.Empty);

        return UsernameAllowedChars.Replace(value, string.Empty);
    }

    public static string SanitizeEmail(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        var value = RemoveControlChars(input.Trim());
        value = HtmlLikeTags.Replace(value, string.Empty)
                            .Replace(" ", string.Empty)
                            .Replace("\"", string.Empty)
                            .Replace("'", string.Empty)
                            .Replace(";", string.Empty)
                            .Replace("--", string.Empty)
                            .ToLowerInvariant();

        return value;
    }

    public static bool IsSafeEmail(string input)
    {
        if (SuspiciousSqlTerms.IsMatch(input))
        {
            return false;
        }

        return EmailValidator.IsValid(input) && StrictEmailPattern.IsMatch(input);
    }

    public static string SanitizePassword(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        var value = RemoveControlChars(input.Trim());
        value = HtmlLikeTags.Replace(value, string.Empty);

        return PasswordAllowedChars.Replace(value, string.Empty);
    }

    public static bool IsValidPasswordInput(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return false;
        }

        return input.All(c => !char.IsControl(c));
    }

    public static bool IsValidRoleName(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        return RoleAllowedChars.IsMatch(input.Trim());
    }

    private static string RemoveControlChars(string input)
    {
        return new string(input.Where(c => !char.IsControl(c)).ToArray());
    }
}
