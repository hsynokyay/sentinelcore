using Microsoft.AspNetCore.Mvc;

public class AuthheaderController : Controller
{
    public IActionResult Echo(string token)
    {
        Response.Headers.Add("Authorization", token);
        return Ok();
    }
}
