using System;
using System.Net.Http;
using AspNet.Owin.Security.Tencent.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace AspNet.Owin.Security.Tencent
{
    public class TencentAuthenticationMiddleware : AuthenticationMiddleware<TencentAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;
        public TencentAuthenticationMiddleware(
            OwinMiddleware next,
             IAppBuilder app,
            TencentAuthenticationOptions options) : base(next, options)
        {
            if (String.IsNullOrWhiteSpace(Options.AppId))
                throw new ArgumentException("app_id或app_key参数无效");

            if (String.IsNullOrWhiteSpace(Options.AppKey))
                throw new ArgumentException("app_id或app_key参数无效");

            if (Options.Provider == null)
                Options.Provider = new TencentAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(TencentAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            _logger = app.CreateLogger<TencentAuthenticationMiddleware>();
            _httpClient = new HttpClient(new WebRequestHandler())
            {
                MaxResponseContentBufferSize = 1024 * 1024 * 10
            };
        }

        protected override AuthenticationHandler<TencentAuthenticationOptions> CreateHandler()
        {
            return new TencentAuthenticationHandler(_httpClient, _logger);
        }
    }
}
