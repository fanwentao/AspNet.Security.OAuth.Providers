# AspNet.Security.OAuth.Providers

OAuth2 authentication middleware for ASP.NET 4.5

## Getting started

**Adding social authentication to your application is a breeze** and just requires a few lines in your `Startup` class:

    app.UseWeChatAuthentication(
        appId:"******",
        appSecret:"******"
    );
    app.UseWeiboAuthentication(
        clientId:"******",
        clientSecret:"******"
    );
    

## NuGet
- **Weibo: [https://www.nuget.org/packages/AspNet.Owin.Security.Weibo/1.0.0](https://www.nuget.org/packages/AspNet.Owin.Security.Weibo/1.0.0)**

