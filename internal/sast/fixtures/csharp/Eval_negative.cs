// internal/sast/fixtures/csharp/Eval_negative.cs
using Microsoft.AspNetCore.Mvc;

public class EvalNegativeController : Controller
{
    public IActionResult Eval(string code)
    {
        // Refuse — compilation of user input is unsupported.
        return BadRequest("evaluation not supported");
    }
}
