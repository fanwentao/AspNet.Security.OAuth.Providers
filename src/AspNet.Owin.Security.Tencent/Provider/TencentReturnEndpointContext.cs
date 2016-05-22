using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace AspNet.Owin.Security.Tencent.Provider
{
    public class TencentReturnEndpointContext : ReturnEndpointContext
    {
        public TencentReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket) :
            base(context, ticket)
        {
        }

    }
}
