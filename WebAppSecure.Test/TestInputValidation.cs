namespace WebAppSecure.Test;

using WebAppSecure.Security;

public class TestInputValidation
{
    [Fact]
    public void TestForSQLInjection()
    {
        var rawUsername = "admin'; DROP TABLE Users;--";
        var rawEmail = "victim@example.com'; DELETE FROM Users;--";

        var sanitizedUsername = InputSanitizer.SanitizeUsername(rawUsername);
        var sanitizedEmail = InputSanitizer.SanitizeEmail(rawEmail);

        Assert.DoesNotContain("'", sanitizedUsername);
        Assert.DoesNotContain(";", sanitizedUsername);
        Assert.DoesNotContain("--", sanitizedUsername);

        Assert.DoesNotContain("'", sanitizedEmail);
        Assert.DoesNotContain(";", sanitizedEmail);
        Assert.False(InputSanitizer.IsSafeEmail(sanitizedEmail));
    }

    [Fact]
    public void TestForXSS()
    {
        var rawUsername = "<script>alert('xss')</script>valid_user";
        var rawEmail = "<img src=x onerror=alert(1)>test@example.com";

        var sanitizedUsername = InputSanitizer.SanitizeUsername(rawUsername);
        var sanitizedEmail = InputSanitizer.SanitizeEmail(rawEmail);

        Assert.DoesNotContain("<", sanitizedUsername);
        Assert.DoesNotContain(">", sanitizedUsername);
        Assert.Equal("alertxssvalid_user", sanitizedUsername);

        Assert.DoesNotContain("<", sanitizedEmail);
        Assert.DoesNotContain(">", sanitizedEmail);
        Assert.Equal("test@example.com", sanitizedEmail);
        Assert.True(InputSanitizer.IsSafeEmail(sanitizedEmail));
    }
}
