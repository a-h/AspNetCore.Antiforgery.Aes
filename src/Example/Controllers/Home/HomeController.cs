using Example.Models;
using Microsoft.AspNetCore.Mvc;

namespace Example.Controllers
{
    public class Home : Controller
    {
        [HttpGet]
        public IActionResult Index()
        {
            return View(new HomeModel());
        }

        [ValidateAntiForgeryToken]
        [HttpPost]
        public IActionResult Index(HomeModel model)
        {
            return View(model);
        }

        [ValidateAntiForgeryToken]
        [HttpPost]
        public IActionResult Index2(HomeModel model)
        {
            model.Say += "_2";
            return View(model);
        }
    }
}