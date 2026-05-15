using Microsoft.AspNetCore.Mvc;

public class CookieController : Controller
{
    public IActionResult Login()
    {
        Response.Cookies.Append("session", "abc123", new CookieOptions { });
        return Ok();
    }
}
