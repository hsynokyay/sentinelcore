// internal/sast/fixtures/csharp/Xxe_positive.cs
using System.Xml;
using Microsoft.AspNetCore.Mvc;

public class XxeController : Controller
{
    public IActionResult Parse(string xml)
    {
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        return Content(doc.DocumentElement.Name);
    }
}
