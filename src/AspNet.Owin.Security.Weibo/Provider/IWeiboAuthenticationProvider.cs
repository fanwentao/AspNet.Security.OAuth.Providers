using System.Threading.Tasks;

namespace AspNet.Owin.Security.Weibo.Provider
{
    public interface IWeiboAuthenticationProvider
    {
        Task Authenticated(WeiboAuthenticatedContext context);

        Task ReturnEndpoint(WeiboReturnEndpointContext context);
        void ApplyRedirect(WeiboApplyRedirectContext context);

    }
}
