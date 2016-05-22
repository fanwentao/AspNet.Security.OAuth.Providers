using System;
using System.Threading.Tasks;
using AspNet.Owin.Security.Core.Common;

namespace AspNet.Owin.Security.WeChat.Provider
{
    public class WeChatAuthenticationProvider : IWeChatAuthenticationProvider
    {
        public WeChatAuthenticationProvider()
        {
            OnAuthenticated = context => TaskHelpers.Completed();
            OnReturnEndpoint = context => TaskHelpers.Completed();
            OnApplyRedirect = context => context.Response.Redirect(context.RedirectUri);
        }

        public Func<WeChatAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<WeChatReturnEndpointContext, Task> OnReturnEndpoint { get; set; }
        public Action<WeChatApplyRedirectContext> OnApplyRedirect { get; set; }

        public virtual Task Authenticated(WeChatAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(WeChatReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }

        public virtual void ApplyRedirect(WeChatApplyRedirectContext context)
        {
            OnApplyRedirect(context);
        }
    }
}
