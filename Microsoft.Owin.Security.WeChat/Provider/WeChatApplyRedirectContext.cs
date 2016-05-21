using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace AspNet.Owin.Security.WeChat.Provider
{
    public class WeChatApplyRedirectContext : BaseContext<WeChatAuthenticationOptions>
    {
        public WeChatApplyRedirectContext(
            IOwinContext context,
            WeChatAuthenticationOptions options,
            string redirectUri,
            AuthenticationProperties properties)
            : base(context, options)
        {
            RedirectUri = redirectUri;
            Properties = properties;
        }

        public string RedirectUri { get; }
        public AuthenticationProperties Properties { get; }
    }
}
