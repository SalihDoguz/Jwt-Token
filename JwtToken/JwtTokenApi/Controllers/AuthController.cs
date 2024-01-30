using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtTokenApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();

        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        { // kullanıcının kaydını almak ve şifresini saklamak.
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.UserName = request.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;


            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            // Kullanıcı Var mı yok mu kontrol
            if (user.UserName != request.UserName)
            { 
                return BadRequest("Kullanıcı Bulunamadı");
            }

            // Kullanıcının giriş yaptığı şifreyi doğrulama metodu
            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Yanlış Şifre!");
            }

            string token = CreateToken(user);
            return Ok(token);
        }


        private string CreateToken(User user)
        {
            List<Claim> claimss = new List<Claim>
            {
                new Claim(ClaimTypes.Name,user.UserName)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            // jwt
            var token = new JwtSecurityToken
                (
                claims:claimss, // yukaridaki bilgileri taşıma
                expires: DateTime.Now.AddDays(1), // tokenin geçerlilik süresi
                signingCredentials: creds
                );
            // string formatına çevirili
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }


        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512()) // HMAC nesnesi 
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password)); // kullanıcının girdiği şifre burada utf 8 ile byte dizisine dönüştürülüyor 
                // bi nevi string karakterde 'lolipop123' şifrem olsun. bunu hasliyor..A%QWE253D
            }
        }
        // Burada hata var bakacağız
        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordHash))
            {
             // Kullanıcının girdiği şifrenin byte dizisine dönüştürülüp, HMACSHA512 algoritması ile hash değeri hesaplanır.
                var computeHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
             // SequenceEqual metodu ile hesaplanan hash değeri ile kaydedilmiş hash değeri karşılaştırılıyor.birbirine eşitse true
                return computeHash.SequenceEqual(passwordHash);
            }

            //using (var hmac = new HMACSHA512(passwordHash))
            //{
            //    var computedSalt = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

            //    // Hash değerlerini karşılaştır
            //    for (int i = 0; i < computedSalt.Length; i++)
            //    {
            //        if (computedSalt[i] != passwordHash[i])
            //        {
            //            return false;
            //        }
            //    }
            //    return true;
            //}

        }
    }
}
