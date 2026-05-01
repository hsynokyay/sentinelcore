// internal/sast/fixtures/csharp/Ssti_negative.cs
using Microsoft.AspNetCore.Mvc;
using RazorEngineCore;

public class SstiNegativeController : Controller
{
    private static readonly RazorEngine Engine = new RazorEngine();
    private static readonly IRazorEngineCompiledTemplate Compiled = Engine.Compile("@Model.Name");

    public IActionResult Render(string name) => Content(Compiled.Run(new { Name = name }));
}
