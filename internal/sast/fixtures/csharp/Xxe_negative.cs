// internal/sast/fixtures/csharp/Xxe_negative.cs
using System.Xml;
using Microsoft.AspNetCore.Mvc;

public class XxeNegativeController : Controller
{
    public IActionResult Parse(string xml)
    {
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);
        return Content(doc.DocumentElement.Name);
    }
}
