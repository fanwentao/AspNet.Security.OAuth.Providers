# AspNet.Security.OAuth.Providers

OAuth2.0 Providers for ASP.NET 4.5 Implementation from **[Katana](http://katanaproject.codeplex.com/)**

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
- **[Weibo](https://www.nuget.org/packages/AspNet.Owin.Security.Weibo/1.0.0)**
- **[WeChat](https://www.nuget.org/packages/AspNet.Owin.Security.WeChat)**
- **[Tencent](https://www.nuget.org/packages/AspNet.Owin.Security.Tencent)**
