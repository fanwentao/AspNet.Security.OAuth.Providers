using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace AspNet.Owin.Security.WeChat.Provider
{
    public class WeChatReturnEndpointContext : ReturnEndpointContext
    {
        public WeChatReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }

    }
}
