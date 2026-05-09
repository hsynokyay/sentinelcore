// internal/sast/fixtures/csharp/Redirect_positive.cs
using Microsoft.AspNetCore.Mvc;

public class RedirectController : Controller
{
    public IActionResult Go(string next) => Redirect(next);
}
