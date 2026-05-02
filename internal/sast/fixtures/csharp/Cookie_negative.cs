using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

public class CookieNegativeController : Controller
{
    public IActionResult Login()
    {
        Response.Cookies.Append("session", "abc123", new CookieOptions
        {
            Secure = true,
            HttpOnly = true,
            SameSite = SameSiteMode.Lax
        });
        return Ok();
    }
}
