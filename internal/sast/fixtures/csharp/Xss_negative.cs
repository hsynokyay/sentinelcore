// internal/sast/fixtures/csharp/Xss_negative.cs
using Microsoft.AspNetCore.Mvc;

public class XssNegativeController : Controller
{
    public IActionResult Echo(string msg)
    {
        ViewBag.Msg = msg;
        return View();
    }
}
