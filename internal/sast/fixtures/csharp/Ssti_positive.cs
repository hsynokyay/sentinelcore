// internal/sast/fixtures/csharp/Ssti_positive.cs
using Microsoft.AspNetCore.Mvc;
using RazorEngineCore;

public class SstiController : Controller
{
    public IActionResult Render(string suffix)
    {
        var engine = new RazorEngine();
        var template = "@Model.Name " + suffix;
        var compiled = engine.Compile(template);
        return Content(compiled.Run(new { Name = "world" }));
    }
}
