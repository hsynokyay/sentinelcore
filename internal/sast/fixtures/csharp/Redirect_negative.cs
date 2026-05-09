// internal/sast/fixtures/csharp/Redirect_negative.cs
using Microsoft.AspNetCore.Mvc;

public class RedirectNegativeController : Controller
{
    public IActionResult Go(string next)
    {
        if (Url.IsLocalUrl(next)) return Redirect(next);
        return Redirect("/");
    }
}
