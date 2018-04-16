using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Management;
using System.Net.Http;
using System.Collections.ObjectModel;
using System.Configuration;
using System.Threading;
using AngleSharp.Dom;
using AngleSharp;
using AngleSharp.Parser.Html;
using AngleSharp.Extensions;
using System.Text.RegularExpressions;
using System.Security.Principal;
using System.Diagnostics;
using System.Reflection;

namespace NetLogin
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
			helper = new LoginHelper();
			UpdateIPLable(helper.GetNowIPAddress());
            DnsComoBox.ItemsSource = new DnsCollection();
            DnsComoBox.DisplayMemberPath = "Name";
            DnsComoBox.SelectedValuePath = "Value";
            System.Configuration.Configuration config = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            UserName.Text= config.AppSettings.Settings["username"].Value;
            UserPass.Password= config.AppSettings.Settings["userpass"].Value;
            this.Closing += (sender, e) =>
              {
                  System.Configuration.Configuration configx = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                  configx.AppSettings.Settings["username"].Value = UserName.Text;
                  configx.AppSettings.Settings["userpass"].Value = UserPass.Password;
                  configx.Save();
              };
			SetAutoLoginThread();
        }
		private void SetAutoLoginThread()
		{
			String username=UserName.Text;
			String password=UserPass.Password;
			int type = NetTypeSelector.SelectedIndex;
			Thread autoLoginThread = new Thread(()=>{
				while(true)
				{
					//Console.WriteLine("test");
					if (helper.IsTimeReady())
					{
						helper.Login(type, username, password);
						Console.WriteLine("Auto Login!");
					}
					else
					{
						Console.WriteLine("Sleep");
						int waitTime = 1000 * 60 * 1;
						Thread.Sleep(waitTime);
					}
						
				}
			});
			autoLoginThread.Start();
		}

		public void UpdateIPLable(String ip)
		{
			IPLabel.Content = ip;
		}
		LoginHelper helper;

		private void LoginClick(object sender, RoutedEventArgs e)
        {
			//TODO:更新IP地址Label
			helper.Login(NetTypeSelector.SelectedIndex, UserName.Text, UserPass.Password);
			UpdateIPLable(helper.GetNowIPAddress());
        }
        private void LogoutClick(object sender, RoutedEventArgs e)
        {
			helper.LogOut(UserName.Text, UserPass.Password);
        }
        
        private void SetDnsClick(object sender, RoutedEventArgs e)
        {
			TyeAdministrator();
			String[] dns = { dns0.Text, dns1.Text };
            if(!LoginHelper.isIPAddress(dns[0])|| !LoginHelper.isIPAddress(dns[1]))
            {
                DnsRight.Content = "DNS地址非法";
                return;
            }
            DnsRight.Content = "";
			helper.SetDns(dns);
        }
        private void AutoDnsClick(object sender, RoutedEventArgs e)
        {
			TyeAdministrator();
			helper.AutoDnsClick();
        }
        private void DnsComoBox_Selected(object sender, RoutedEventArgs e)
        {
            String[] x = (String[])DnsComoBox.SelectedValue;
            dns0.Text = x[0];
            dns1.Text = x[1];
        }
		private bool TyeAdministrator()
		{
			var wi = WindowsIdentity.GetCurrent();
			if (wi == null) return false;
			var wp = new WindowsPrincipal(wi);
			var runAsAdmin = wp.IsInRole(WindowsBuiltInRole.Administrator);
			if(!runAsAdmin)
			{
				ProcessStartInfo psi = new ProcessStartInfo();
				psi.FileName = Assembly.GetExecutingAssembly().Location;
				psi.Verb = "runas";
				Console.WriteLine(psi.FileName);
				//return;
				try
				{
					Process.Start(psi);
					Application.Current.Shutdown();
				}
				catch (Exception eee)
				{
					MessageBox.Show(eee.Message);
				}
			}
			return true;
		}
	}
	class LoginHelper
	{
		public LoginHelper()
		{
			NowIPAdress = getEthernetIP();
		}
		private DateTime nowTime;
		private String loginUrl = "http://219.229.251.2/srun_portal_pc.php?ac_id=1&ip=";
		private String NowIPAdress = "";
		private String UserName;
		private String Password;
		public bool IsTimeReady()
		{
			if (nowTime == null) return true;
			TimeSpan diff = DateTime.Now.Subtract(nowTime);
			Console.WriteLine(nowTime.ToString() + " " + DateTime.Now.ToString() + " " + diff.TotalMinutes);
			return diff.TotalMinutes > 10;
		}
		public String GetNowIPAddress()
		{
			return NowIPAdress;
		}
		private String Utf16ToUtf8(String utf16String)
		{
			// Get UTF16 bytes and convert UTF16 bytes to UTF8 bytes
			byte[] utf16Bytes = Encoding.Unicode.GetBytes(utf16String);
			byte[] utf8Bytes = Encoding.Convert(Encoding.Unicode, Encoding.UTF8, utf16Bytes);

			// Return UTF8 bytes as ANSI string
			return Encoding.Default.GetString(utf8Bytes);
		}
		private String ConvertEncode(String s)
		{
			s = Utf16ToUtf8(s);
			byte[] b = System.Text.Encoding.Default.GetBytes(s);
			//转成 Base64 形式的 System.String  
			s = Convert.ToBase64String(b);
			Console.WriteLine(s);
			return s;
		}
		
		private void UpdateUserInfo(String UserName, String Password)
		{
			this.UserName = UserName;
			this.Password = Password;
		}
		public void LogOut(String UserName, String Password)
		{
			UpdateUserInfo(UserName, Password);
			HttpClient client = new HttpClient();
			client.DefaultRequestHeaders.Add("user-agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36");
			List<KeyValuePair<String, String>> form = new List<KeyValuePair<String, String>>();
			form.Add(new KeyValuePair<String, String>("action", "logout"));
			form.Add(new KeyValuePair<String, String>("username", UserName));
			form.Add(new KeyValuePair<String, String>("ajax", "1"));
			client.PostAsync(new Uri(loginUrl + NowIPAdress), new FormUrlEncodedContent(form));
		}
		public static bool isIPAddress(String s)
		{
			String[] Values = s.Split('.');
			if (Values.Count() != 4) return false;
			int num;
			for (int i = 0; i < 4; i++)
			{
				if (Int32.TryParse(Values[i], out num))
				{
					if (num < 0 || num >= 256) return false;
				}
				else return false;
			}
			return true;
		}
		public void SetDns(String[] dns)
		{
			ManagementBaseObject inPar = null;
			ManagementBaseObject outPar = null;
			ManagementClass mc = new ManagementClass("Win32_NetworkAdapterConfiguration");
			ManagementObjectCollection moc = mc.GetInstances();
			foreach (ManagementObject item in moc)
			{
				if (!(bool)item["IPEnabled"])
					continue;
				String s = (item.GetPropertyValue("IPAddress") as String[])[0];
				if (s.Trim() == NowIPAdress.Trim())
				{
					inPar = item.GetMethodParameters("SetDNSServerSearchOrder");
					inPar["DNSServerSearchOrder"] = new string[] { dns[0], dns[1] }; // 1.DNS 2.备用DNS 
					outPar = item.InvokeMethod("SetDNSServerSearchOrder", inPar, null);
					Console.WriteLine(dns[0] + "\n" + dns[1]);
					break;
				}
			}
		}
		public void Login(int NetType, String UserName, String Password)
		{
			nowTime = DateTime.Now;
			UpdateUserInfo(UserName.Trim(), Password);
			HttpClient client = new HttpClient();
			client.DefaultRequestHeaders.Add("user-agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36");
			List<KeyValuePair<String, String>> form = new List<KeyValuePair<String, String>>();
			form.Add(new KeyValuePair<String, String>("action", "login"));
			form.Add(new KeyValuePair<String, String>("username", UserName.Trim()));
			form.Add(new KeyValuePair<String, String>("password", "{B}" + ConvertEncode(Password)));
			form.Add(new KeyValuePair<String, String>("ac_id", "1"));
			form.Add(new KeyValuePair<String, String>("user_ip", NowIPAdress));
			form.Add(new KeyValuePair<String, String>("nas_ip", ""));
			form.Add(new KeyValuePair<String, String>("user_mac", ""));
			form.Add(new KeyValuePair<String, String>("save_me", "0"));
			form.Add(new KeyValuePair<String, String>("ajax", "1"));
			if (NetType == 0)
			{
				NowIPAdress = getEthernetIP();
				client.PostAsync(new Uri(loginUrl + NowIPAdress), new FormUrlEncodedContent(form));
			}
			if (NetType == 1)
			{
				HttpResponseMessage response;
				response = client.GetAsync(new Uri(loginUrl + "10.100.1.1")).Result;
				var responseString =response.Content.ReadAsStringAsync().Result;
				var parser = new HtmlParser();
				var document = parser.Parse(responseString);
				String pat = @"10.100.1.*\s";
				Console.WriteLine(document.GetElementsByTagName("li")[2].ToHtml());
				Match match = Regex.Match(document.GetElementsByTagName("li")[2].ToHtml(), pat);
				String ips = "null";
				if (!match.Success) Console.WriteLine("Wi-Fi IP match wrong! " + match.Length);
				else ips = match.Groups[0].ToString().Trim();
				Console.WriteLine(ips);
				form[4] = new KeyValuePair<String, String>("user_ip", ips);
			}
		}
		public void AutoDnsClick()
		{
			ManagementBaseObject inPar = null;
			ManagementBaseObject outPar = null;
			ManagementClass mc = new ManagementClass("Win32_NetworkAdapterConfiguration");
			ManagementObjectCollection moc = mc.GetInstances();
			foreach (ManagementObject item in moc)
			{
				if (!(bool)item["IPEnabled"])
					continue;
				inPar = item.GetMethodParameters("EnableStatic");
				String s = (item.GetPropertyValue("IPAddress") as String[])[0];
				if (s.Trim() == NowIPAdress.Trim())
				{
					item.InvokeMethod("EnableDHCP", null);
					break;
				}
			}
		}
		private String getEthernetIP()
		{
			String ips = "null";
			NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
			foreach (var netItem in nics)
			{
				if (netItem.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
				{
					foreach (var x in netItem.GetIPProperties().UnicastAddresses)
					{
						Console.WriteLine(x.Address);
						if (x.Address.ToString().Substring(0, 2) == "10")
						{
							ips = x.Address.ToString();
						}
					}
				}
			}
			if (ips == "null")
				Console.WriteLine("IP not found");
			NowIPAdress = ips;
			return ips;
		}
	}
    public class DnsItem
    {
        public String Name { get; set; }
        public String[] Value { get; set; }
    }
    public class DnsCollection : ObservableCollection<DnsItem>
    {
        public DnsCollection()
        {            
            Add(new DnsItem { Name = "上海电信", Value = new string[] { "202.96.209.133", "116.228.111.118" } });
            Add(new DnsItem { Name = "阿里DNS", Value = new string[]{ "223.5.5.5", "223.6.6.6" } });
            Add(new DnsItem { Name = "中科大DNS", Value = new string[] { "202.38.64.1", "202.112.20.131" } });
            Add(new DnsItem { Name = "SDNS(by CNNIC)", Value = new string[] { "1.2.4.8", "210.2.4.8" } });
        }
    }
}
