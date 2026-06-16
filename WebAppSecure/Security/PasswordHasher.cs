namespace WebAppSecure.Security;

using System.Security.Cryptography;
using System.Text;

public static class PasswordHasher
{
    private const string Algorithm = "SHA256";
    private const int Iterations = 120_000;
    private const int SaltSize = 16;
    private const int KeySize = 32;

    public static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var key = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            KeySize);

        return $"PBKDF2${Algorithm}${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(key)}";
    }

    public static bool VerifyPassword(string password, string storedHash)
    {
        if (string.IsNullOrWhiteSpace(storedHash))
        {
            return false;
        }

        if (!storedHash.StartsWith("PBKDF2$", StringComparison.Ordinal))
        {
            // Backward compatibility for old SHA-256 entries.
            return VerifyLegacySha256(password, storedHash);
        }

        var parts = storedHash.Split('$', StringSplitOptions.None);
        if (parts.Length != 5)
        {
            return false;
        }

        var algorithm = parts[1];
        if (!string.Equals(algorithm, Algorithm, StringComparison.Ordinal))
        {
            return false;
        }

        if (!int.TryParse(parts[2], out var iterations) || iterations < 10_000)
        {
            return false;
        }

        byte[] salt;
        byte[] expectedKey;
        try
        {
            salt = Convert.FromBase64String(parts[3]);
            expectedKey = Convert.FromBase64String(parts[4]);
        }
        catch (FormatException)
        {
            return false;
        }

        var actualKey = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            expectedKey.Length);

        return CryptographicOperations.FixedTimeEquals(actualKey, expectedKey);
    }

    private static bool VerifyLegacySha256(string password, string storedHash)
    {
        var bytes = Encoding.UTF8.GetBytes(password);
        var hash = SHA256.HashData(bytes);
        var computedHash = Convert.ToHexString(hash);

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(computedHash),
            Encoding.UTF8.GetBytes(storedHash));
    }
}