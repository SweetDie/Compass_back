using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Compass.Services
{
    public class ServiceResponse
    {
        public string AccessToken { get; set; } = null;
        public string RefreshToken { get; set; } = null;
        public string Message { get; set; } = null;
        public object Payload { get; set; } = null;
        public bool IsSuccess { get; set; } = false;
        public IEnumerable<string> Errors { get; set; } = null;
    }
}
