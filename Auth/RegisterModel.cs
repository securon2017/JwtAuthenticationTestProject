using System.ComponentModel.DataAnnotations;

namespace JwtAuthenticationTestProject.Auth
{
    public class RegisterModel
    {
        [Required (ErrorMessage ="User Name is requared")]
        public string? UserName { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "Email is requared")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "Password is requared")]
        public string? Password { get; set; }
    }
}
