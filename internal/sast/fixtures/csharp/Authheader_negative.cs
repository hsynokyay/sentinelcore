using System;
using Microsoft.AspNetCore.Mvc;

public class AuthheaderNegativeController : Controller
{
    public IActionResult Echo()
    {
        Response.Headers.Add("Authorization", "Bearer " + Environment.GetEnvironmentVariable("SERVICE_TOKEN"));
        return Ok();
    }
}
