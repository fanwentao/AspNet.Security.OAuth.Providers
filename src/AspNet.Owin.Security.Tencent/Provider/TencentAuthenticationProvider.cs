using System;
using System.Threading.Tasks;

namespace AspNet.Owin.Security.Tencent.Provider
{
    public class TencentAuthenticationProvider : ITencentAuthenticationProvider
    {
        public TencentAuthenticationProvider()
        {
            OnAuthenticated = context => Task.CompletedTask;
            OnReturnEndpoint = context => Task.CompletedTask;
            OnApplyRedirect = context => context.Response.Redirect(context.RedirectUri);
        }

        public Func<TencentAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<TencentReturnEndpointContext, Task> OnReturnEndpoint { get; set; }
        public Action<TencentApplyRedirectContext> OnApplyRedirect { get; set; }

        public virtual Task Authenticated(TencentAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(TencentReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }

        public virtual void ApplyRedirect(TencentApplyRedirectContext context)
        {
            OnApplyRedirect(context);
        }
    }
}
