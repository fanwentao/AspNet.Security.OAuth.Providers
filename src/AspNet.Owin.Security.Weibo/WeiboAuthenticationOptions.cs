using AspNet.Owin.Security.Weibo.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace AspNet.Owin.Security.Weibo
{
    public class WeiboAuthenticationOptions : AuthenticationOptions
    {
        public WeiboAuthenticationOptions() : base(Constants.DefaultAuthenticationType)
        {
            AuthenticationType = Constants.DefaultAuthenticationType;
            Caption = Constants.DefaultAuthenticationType;
            AuthenticationMode = AuthenticationMode.Passive;
            CallbackPath = new PathString(Constants.CallbackPath);

            AuthorizationEndpoint = Constants.AuthorizationEndpoint;
            TokenEndpoint = Constants.TokenEndpoint;
            UserInformationEndpoint = Constants.UserInformationEndpoint;
        }

        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string SignInAsAuthenticationType { get; set; }
        public PathString CallbackPath { get; set; }
        public string AuthorizationEndpoint { get; set; }
        public string TokenEndpoint { get; set; }
        public string UserInformationEndpoint { get; set; }
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        public IWeiboAuthenticationProvider Provider { get; set; }
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }
    }
}
