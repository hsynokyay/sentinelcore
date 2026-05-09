// internal/sast/fixtures/csharp/Xss_positive.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Html;

public class XssController : Controller
{
    public IActionResult Echo(string msg)
    {
        ViewBag.Msg = new HtmlString(msg);
        return View();
    }
}
