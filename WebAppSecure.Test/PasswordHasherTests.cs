namespace WebAppSecure.Test;

using WebAppSecure.Security;

public class PasswordHasherTests
{
    [Fact]
    public void HashPassword_GeneratesPbkdf2Format_AndVerifies()
    {
        var password = "StrongPass123!";

        var hash = PasswordHasher.HashPassword(password);

        Assert.StartsWith("PBKDF2$SHA256$", hash, StringComparison.Ordinal);
        Assert.True(PasswordHasher.VerifyPassword(password, hash));
        Assert.False(PasswordHasher.VerifyPassword("wrong-password", hash));
    }

    [Fact]
    public void HashPassword_GeneratesDifferentHashes_ForSamePassword()
    {
        var password = "SamePassword!123";

        var hash1 = PasswordHasher.HashPassword(password);
        var hash2 = PasswordHasher.HashPassword(password);

        Assert.NotEqual(hash1, hash2);
        Assert.True(PasswordHasher.VerifyPassword(password, hash1));
        Assert.True(PasswordHasher.VerifyPassword(password, hash2));
    }
}
