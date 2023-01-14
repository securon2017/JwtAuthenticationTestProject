using System.ComponentModel.DataAnnotations;

namespace JwtAuthenticationTestProject.Auth
{
    public class LoginModel
    {
        [Required(ErrorMessage = "User Name is requared")]
        public string? UserName { get; set; }

        [Required(ErrorMessage = "Password is requared")]
        public string? Password { get; set; }

    }
}
