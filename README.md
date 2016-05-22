# OAuth2.0 基于OWIN外部登录中间件实现


项目代码结构和基础实现源自 **[Katana](http://katanaproject.codeplex.com/)** 项目,我只做了一点微小的工作,更多细节请查看项目 **[源代码](http://katanaproject.codeplex.com/SourceControl/latest#README)**.



## NuGet

- **[Weibo](https://www.nuget.org/packages/AspNet.Owin.Security.Weibo/1.0.0)**
- **[WeChat](https://www.nuget.org/packages/AspNet.Owin.Security.WeChat)**
- **[Tencent](https://www.nuget.org/packages/AspNet.Owin.Security.Tencent)**



## 入门

配置外部登录应用ClientId和ClientSecret值,并添加如下代码到 `Startup` class:

    app.UseWeChatAuthentication(
        appId:"******",
        appSecret:"******"
    );
    app.UseWeiboAuthentication(
        clientId:"******",
        clientSecret:"******"
    );
    


