using Server.Models;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Description;

namespace Server.Controllers
{
    public class HelloWorldController : ApiController
    {

        // GET api/<controller>
        public HttpResponseMessage Get()
        {
            return  new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("Hello world")
            };
        }

        // POST api/<controller>
        [ResponseType(typeof(string))]
        public HttpResponseMessage Post(ContentData data)
        {
            Trace.WriteLine($"Content recived from the client: '{data.Content}'");

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($"Received the following content from the client: '{data.Content}'.")
            };
        }
    }
}