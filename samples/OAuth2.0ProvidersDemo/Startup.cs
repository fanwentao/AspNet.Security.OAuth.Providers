using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(OAuth2._0ProvidersDemo.Startup))]
namespace OAuth2._0ProvidersDemo
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
