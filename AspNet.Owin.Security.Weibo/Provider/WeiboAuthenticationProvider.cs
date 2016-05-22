using System;
using System.Threading.Tasks;
using AspNet.Owin.Security.Core.Common;

namespace AspNet.Owin.Security.Weibo.Provider
{
    public class WeiboAuthenticationProvider : IWeiboAuthenticationProvider
    {
        public WeiboAuthenticationProvider()
        {
            OnAuthenticated = context => TaskHelpers.Completed();
            OnReturnEndpoint = context => TaskHelpers.Completed();
            OnApplyRedirect = context => context.Response.Redirect(context.RedirectUri);
        }

        public Func<WeiboAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<WeiboReturnEndpointContext, Task> OnReturnEndpoint { get; set; }
        public Action<WeiboApplyRedirectContext> OnApplyRedirect { get; set; }
        public Task Authenticated(WeiboAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public Task ReturnEndpoint(WeiboReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }

        public void ApplyRedirect(WeiboApplyRedirectContext context)
        {
            OnApplyRedirect(context);
        }
    }
}
