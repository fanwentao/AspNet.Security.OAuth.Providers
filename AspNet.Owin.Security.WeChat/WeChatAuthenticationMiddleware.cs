using System;
using System.Net.Http;
using AspNet.Owin.Security.WeChat.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace AspNet.Owin.Security.WeChat
{
    public class WeChatAuthenticationMiddleware : AuthenticationMiddleware<WeChatAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;
        public WeChatAuthenticationMiddleware(
            OwinMiddleware next,
            IAppBuilder app,
            WeChatAuthenticationOptions options) : base(next, options)
        {
            if (String.IsNullOrWhiteSpace(Options.AppId))
                throw new ArgumentException("app_id或app_secret参数无效");

            if (String.IsNullOrWhiteSpace(Options.AppSecret))
                throw new ArgumentException("app_id或app_secret参数无效");

            if (Options.Provider == null)
                Options.Provider = new WeChatAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(WeChatAuthenticationHandler).FullName, Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            _logger = app.CreateLogger<WeChatAuthenticationMiddleware>();

            _httpClient = new HttpClient
            {
                MaxResponseContentBufferSize = 1024 * 1024 * 10
            };
        }

        protected override AuthenticationHandler<WeChatAuthenticationOptions> CreateHandler()
        {
            return new WeChatAuthenticationHandler(_logger, _httpClient);
        }
    }
}
