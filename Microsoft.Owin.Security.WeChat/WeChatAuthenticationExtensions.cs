using System;
using Owin;

namespace AspNet.Owin.Security.WeChat
{
    public static class WeChatAuthenticationExtensions
    {
        public static IAppBuilder UseWeChatAuthentication(this IAppBuilder app, WeChatAuthenticationOptions options)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (options == null) throw new ArgumentNullException(nameof(options));

            app.Use(typeof(WeChatAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseWeChatAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));

            app.Use(typeof(WeChatAuthenticationMiddleware), app, new WeChatAuthenticationOptions
            {
                AppId = appId,
                AppSecret = appSecret
            });
            return app;
        }
    }
}
