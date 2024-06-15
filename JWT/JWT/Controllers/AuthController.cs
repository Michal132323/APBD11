using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;

        public AuthController(IConfiguration config)
        {
            _config = config;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequestModel model)
        {
            //Tymczasowe zmienne, w normalnym przypadku wartości pobrano by z bazy danych
            if (model.UserName.ToLower() != "Name" || model.Password != "Password")
            {
                return Unauthorized("Wrong username or password");
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = GenerateToken(tokenHandler, _config["JWT:Issuer"], _config["JWT:Audience"], _config["JWT:Key"], 15);
            var refreshToken = GenerateToken(tokenHandler, _config["JWT:RefIssuer"], _config["JWT:RefAudience"], _config["JWT:RefKey"], 4320); // 3 days

            return Ok(new LoginResponseModel { Token = token, RefreshToken = refreshToken });
        }

        [HttpPost("refresh")]
        public IActionResult RefreshToken([FromBody] RefreshTokenRequestModel requestModel)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                tokenHandler.ValidateToken(requestModel.RefreshToken, new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = _config["JWT:RefIssuer"],
                    ValidAudience = _config["JWT:RefAudience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:RefKey"]))
                }, out SecurityToken validatedToken);

                var token = GenerateToken(tokenHandler, _config["JWT:Issuer"], _config["JWT:Audience"], _config["JWT:Key"], 15);
                var refreshToken = GenerateToken(tokenHandler, _config["JWT:RefIssuer"], _config["JWT:RefAudience"], _config["JWT:RefKey"], 4320); // 3 days

                return Ok(new LoginResponseModel { Token = token, RefreshToken = refreshToken });
            }
            catch
            {
                return Unauthorized("Invalid refresh token");
            }
        }

        [HttpPost("register")]
        public IActionResult Register([FromBody] RegisterRequestModel model)
        {
            if (UserExists(model.UserName))
            {
                return BadRequest("User already exists");
            }

            var hashedPassword = HashPassword(model.Password);
            CreateUser(model.UserName, hashedPassword);

            return Ok("User registered successfully");
        }

        private string GenerateToken(JwtSecurityTokenHandler tokenHandler, string issuer, string audience, string key, int expiryMinutes)
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Audience = audience,
                Expires = DateTime.UtcNow.AddMinutes(expiryMinutes),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private bool UserExists(string username)
        {
            return false; // Placeholder
        }

        private void CreateUser(string username, string hashedPassword)
        {
            //Placeholder
        }

        private string HashPassword(string password)
        {
            using var hmac = new HMACSHA512();
            var salt = hmac.Key;
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
        }
    }

    public class LoginRequestModel
    {
        public string UserName { get; set; } = null!;
        public string Password { get; set; } = null!;
    }

    public class LoginResponseModel
    {
        public string Token { get; set; } = null!;
        public string RefreshToken { get; set; } = null!;
    }

    public class RefreshTokenRequestModel
    {
        public string RefreshToken { get; set; } = null!;
    }

    public class RegisterRequestModel
    {
        public string UserName { get; set; } = null!;
        public string Password { get; set; } = null!;
    }
}