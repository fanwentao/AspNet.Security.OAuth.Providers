using System;
using System.Net.Http;
using AspNet.Owin.Security.Weibo.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace AspNet.Owin.Security.Weibo
{
    public class WeiboAuthenticationMiddleware : AuthenticationMiddleware<WeiboAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public WeiboAuthenticationMiddleware(
            OwinMiddleware next,
            IAppBuilder app,
            WeiboAuthenticationOptions options) : base(next, options)
        {
            if (String.IsNullOrWhiteSpace(Options.ClientId))
                throw new ArgumentException("client_id或client_secret参数无效");

            if (String.IsNullOrWhiteSpace(Options.ClientSecret))
                throw new ArgumentException("client_id或client_secret参数无效");

            if (String.IsNullOrWhiteSpace(Options.SignInAsAuthenticationType))
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            if (Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(WeiboAuthenticationMiddleware).FullName,
                    Options.AuthenticationType,
                    "v1");

                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (Options.Provider == null)
                Options.Provider = new WeiboAuthenticationProvider();

            _logger = app.CreateLogger<WeiboAuthenticationMiddleware>();
            _httpClient = new HttpClient
            {
                MaxResponseContentBufferSize = 1024 * 1024 * 10
            };
        }

        protected override AuthenticationHandler<WeiboAuthenticationOptions> CreateHandler()
        {
            return new WeiboAuthenticationHandler(_httpClient, _logger);
        }
    }
}
