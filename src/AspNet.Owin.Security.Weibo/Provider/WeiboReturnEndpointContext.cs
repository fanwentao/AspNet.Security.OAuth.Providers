using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace AspNet.Owin.Security.Weibo.Provider
{
    public class WeiboReturnEndpointContext : ReturnEndpointContext
    {
        public WeiboReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket) : base(context, ticket)
        {
        }

    }
}
