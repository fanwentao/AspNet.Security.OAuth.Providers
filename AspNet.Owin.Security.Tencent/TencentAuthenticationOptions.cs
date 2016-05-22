using System.Collections.Generic;
using AspNet.Owin.Security.Tencent.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace AspNet.Owin.Security.Tencent
{
    public class TencentAuthenticationOptions : AuthenticationOptions
    {
        public TencentAuthenticationOptions() : base(Constants.DefaultAuthenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            Scope = new List<string>
            {
                "get_user_info"
            };
            CallbackPath = new PathString(Constants.CallbackPath);
            AuthenticationMode = AuthenticationMode.Passive;
            AuthorizationEndpoint = Constants.AuthorizationEndpoint;
            UserInformationEndpoint = Constants.UserInformationEndpoint;
            OptionIdEndpoint = Constants.OptionIdEndpoint;
            TokenEndpoint = Constants.TokenEndpoint;
        }
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }
        public string AuthorizationEndpoint { get; set; }
        public string TokenEndpoint { get; set; }
        public string UserInformationEndpoint { get; set; }
        public string OptionIdEndpoint { get; set; }
        public string AppId { get; set; }
        public string AppKey { get; set; }
        public PathString CallbackPath { get; set; }
        public string SignInAsAuthenticationType { get; set; }
        public IList<string> Scope { get; private set; }
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        public ITencentAuthenticationProvider Provider { get; set; }
    }
}
