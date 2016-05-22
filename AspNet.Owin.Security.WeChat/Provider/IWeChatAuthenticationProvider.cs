using System.Threading.Tasks;

namespace AspNet.Owin.Security.WeChat.Provider
{
    public interface IWeChatAuthenticationProvider
    {
        Task Authenticated(WeChatAuthenticatedContext context);

        Task ReturnEndpoint(WeChatReturnEndpointContext context);
        void ApplyRedirect(WeChatApplyRedirectContext context);
    }
}
