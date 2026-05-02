// internal/sast/fixtures/csharp/Log_positive.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

public class LogController : Controller
{
    private readonly ILogger _log;
    public LogController(ILogger<LogController> log) { _log = log; }

    public IActionResult Login(string user)
    {
        _log.LogInformation("Login attempt: " + user);
        return Ok();
    }
}
