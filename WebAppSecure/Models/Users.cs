namespace WebAppSecure.Models;

using System.ComponentModel.DataAnnotations;

public class Users
{
    [Key]
    public int UserID { get; set; }

    [Required]
    [StringLength(100)]
    public string Username { get; set; } = null!;

    [Required]
    [EmailAddress]
    [StringLength(100)]
    public string Email { get; set; } = null!;

    [Required]
    [StringLength(512)]
    public string PasswordHash { get; set; } = null!;
}