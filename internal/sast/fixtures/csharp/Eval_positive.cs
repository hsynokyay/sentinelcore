// internal/sast/fixtures/csharp/Eval_positive.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.CSharp;
using System.CodeDom.Compiler;

public class EvalController : Controller
{
    public IActionResult Eval(string code)
    {
        using var provider = new CSharpCodeProvider();
        var result = provider.CompileAssemblyFromSource(new CompilerParameters(), code);
        return Ok(result.PathToAssembly);
    }
}
