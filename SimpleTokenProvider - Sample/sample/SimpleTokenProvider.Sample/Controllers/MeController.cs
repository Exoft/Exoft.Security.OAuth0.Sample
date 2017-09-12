using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SimpleTokenProvider.Sample.Controllers
{
    [Route("api/[controller]")]
   
    public class MeController : Controller
    {
        [Authorize(Roles = "ExoftAdmin")]
        public string Get()
        {
            // The JWT "sub" claim is automatically mapped to ClaimTypes.NameIdentifier
            // by the UseJwtBearerAuthentication middleware
            var username = HttpContext.User.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value;

            var role = HttpContext.User.Claims.First(c => c.Type == ClaimTypes.Role).Value;

            return $"Hello {username}! Your Role is: {role}";
        }

        [Authorize]
        [HttpGet]
        public string GetWithoutRoleSpecified()
        {
            var username = HttpContext.User.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value;

            return $"Hello {username}!";
        }
    }

}
