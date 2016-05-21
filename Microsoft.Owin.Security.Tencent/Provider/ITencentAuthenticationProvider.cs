using System.Threading.Tasks;

namespace AspNet.Owin.Security.Tencent.Provider
{
    public interface ITencentAuthenticationProvider
    {
        Task Authenticated(TencentAuthenticatedContext context);

        Task ReturnEndpoint(TencentReturnEndpointContext context);

        void ApplyRedirect(TencentApplyRedirectContext context);
    }
}
