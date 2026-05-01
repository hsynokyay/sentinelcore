// internal/sast/fixtures/csharp/Log_negative.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

public class LogNegativeController : Controller
{
    private readonly ILogger _log;
    public LogNegativeController(ILogger<LogNegativeController> log) { _log = log; }

    public IActionResult Login(string user)
    {
        _log.LogInformation("Login attempt: {User}", user);
        return Ok();
    }
}
