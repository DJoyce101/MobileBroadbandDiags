using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace MbnDiagnostics
{
    public partial class TcpIpWindow : Window, INotifyPropertyChanged
    {
        private readonly DispatcherTimer _pingTimer;

        public ObservableCollection<NetworkInterfaceInfo> Interfaces { get; } = new();

        private NetworkInterfaceInfo? _selectedInterface;
        public NetworkInterfaceInfo? SelectedInterface
        {
            get => _selectedInterface;
            set
            {
                if (_selectedInterface != value)
                {
                    _selectedInterface = value;
                    OnPropertyChanged();
                    _ = RefreshPings();
                }
            }
        }

        private string _defaultGatewayPing;
        public string DefaultGatewayPing
        {
            get => _defaultGatewayPing;
            set
            {
                if (_defaultGatewayPing != value)
                {
                    _defaultGatewayPing = value;
                    OnPropertyChanged();
                }
            }
        }

        private string _primaryDnsPing;
        public string PrimaryDnsPing
        {
            get => _primaryDnsPing;
            set
            {
                if (_primaryDnsPing != value)
                {
                    _primaryDnsPing = value;
                    OnPropertyChanged();
                }
            }
        }

        private string _secondaryDnsPing;
        public string SecondaryDnsPing
        {
            get => _secondaryDnsPing;
            set
            {
                if (_secondaryDnsPing != value)
                {
                    _secondaryDnsPing = value;
                    OnPropertyChanged();
                }
            }
        }

        private string _googlePing;
        public string GooglePing
        {
            get => _googlePing;
            set
            {
                if (_googlePing != value)
                {
                    _googlePing = value;
                    OnPropertyChanged();
                }
            }
        }

        private string _fontanaPing;
        public string FontanaPing
        {
            get => _fontanaPing;
            set
            {
                if (_fontanaPing != value)
                {
                    _fontanaPing = value;
                    OnPropertyChanged();
                }
            }
        }

        private string _fontanaPdPing;
        public string FontanaPdPing
        {
            get => _fontanaPdPing;
            set
            {
                if (_fontanaPdPing != value)
                {
                    _fontanaPdPing = value;
                    OnPropertyChanged();
                }
            }
        }

        public TcpIpWindow()
        {
            InitializeComponent();
            DataContext = this;
            Loaded += TcpIpWindow_Loaded;

            _pingTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(3)
            };
            _pingTimer.Tick += async (s, e) => await RefreshPings();
        }

        private void TcpIpWindow_Loaded(object? sender, RoutedEventArgs e)
        {
            try
            {
                Interfaces.Clear();
                foreach (var nic in SafeEnumerateInterfaces())
                    Interfaces.Add(nic);

                if (Interfaces.Count > 0)
                    SelectedInterface = Interfaces[0];

                _pingTimer.Start();
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    this,
                    $"Error initializing TCP/IP window:\n{ex.Message}",
                    "TCP/IP",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void InterfaceComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (sender is ComboBox cb && cb.SelectedItem is NetworkInterfaceInfo nii)
            {
                SelectedInterface = nii;
            }
        }

        private async Task RefreshPings()
        {
            if (SelectedInterface == null || SelectedInterface.OperationalStatus != "Up")
            {
                DefaultGatewayPing = "N/A (Interface Down)";
                PrimaryDnsPing = "N/A (Interface Down)";
                SecondaryDnsPing = "N/A (Interface Down)";
                GooglePing = "N/A (Interface Down)";
                FontanaPing = "N/A (Interface Down)";
                FontanaPdPing = "N/A (Interface Down)";
                return;
            }

            await Task.WhenAll(
                PingAsync(SelectedInterface.DefaultGateway, ping => DefaultGatewayPing = ping),
                PingAsync(SelectedInterface.PrimaryDns, ping => PrimaryDnsPing = ping),
                PingAsync(SelectedInterface.SecondaryDns, ping => SecondaryDnsPing = ping),
                PingAsync("google.com", ping => GooglePing = ping),
                PingAsync("mobility.fontana.org", ping => FontanaPing = ping),
                PingAsync("mobility.fontanapd.org", ping => FontanaPdPing = ping)
            );
        }

        private async Task PingAsync(string host, Action<string> updateAction)
        {
            if (string.IsNullOrWhiteSpace(host))
            {
                updateAction("N/A");
                return;
            }

            // Check if the host is an IPv6 address
            if (IPAddress.TryParse(host, out IPAddress address) && address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                updateAction("IPv6 Address (Skipped)");
                return;
            }

            try
            {
                var pingSender = new Ping();
                var reply = await pingSender.SendPingAsync(host, 1000); // 1-second timeout

                if (reply.Status == IPStatus.Success)
                {
                    updateAction($"{reply.RoundtripTime}ms ({reply.Address})");
                }
                else
                {
                    updateAction($"Failed ({reply.Status})");
                }
            }
            catch (Exception ex)
            {
                updateAction($"Error ({ex.Message})");
            }
        }

        private static ObservableCollection<NetworkInterfaceInfo> SafeEnumerateInterfaces()
        {
            var list = new ObservableCollection<NetworkInterfaceInfo>();

            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic == null) continue;

                // Exclude Bluetooth interfaces and other unwanted types
                if (nic.Description.Contains("bluetooth", StringComparison.OrdinalIgnoreCase) ||
                    nic.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                    nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel)
                    continue;

                bool hasIPv4 = false, hasIPv6 = false;
                try
                {
                    hasIPv4 = nic.Supports(NetworkInterfaceComponent.IPv4);
                    hasIPv6 = nic.Supports(NetworkInterfaceComponent.IPv6);
                }
                catch { }
                if (!hasIPv4 && !hasIPv6) continue;

                IPInterfaceProperties ipProps;
                try
                {
                    ipProps = nic.GetIPProperties();
                    if (ipProps == null) continue;
                }
                catch (NetworkInformationException)
                {
                    continue;
                }
                catch
                {
                    continue;
                }

                var info = new NetworkInterfaceInfo
                {
                    Id = nic.Id,
                    Name = nic.Name,
                    Description = nic.Description,
                    Type = nic.NetworkInterfaceType.ToString(),
                    OperationalStatus = nic.OperationalStatus.ToString(),
                    SpeedMbps = nic.Speed > 0 ? nic.Speed / 1_000_000 : 0,
                    MacAddress = FormatMac(nic.GetPhysicalAddress()),
                    Priority =
                        (nic.Description.Contains("mobile", StringComparison.OrdinalIgnoreCase) ||
                         nic.Description.Contains("cellular", StringComparison.OrdinalIgnoreCase) ||
                         nic.Description.Contains("broadband", StringComparison.OrdinalIgnoreCase) ||
                         nic.NetworkInterfaceType == NetworkInterfaceType.Ppp) ? 1 :
                        nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet ? 2 :
                        nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? 3 : 4
                };

                try
                {
                    foreach (var ua in ipProps.UnicastAddresses)
                    {
                        if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            info.IPv4Address = ua.Address.ToString();
                            info.IPv4Mask = ua.IPv4Mask?.ToString() ?? string.Empty;
                        }
                        else if (ua.Address.AddressFamily == AddressFamily.InterNetworkV6)
                        {
                            if (string.IsNullOrEmpty(info.IPv6Address))
                                info.IPv6Address = ua.Address.ToString();
                        }
                    }
                }
                catch { }

                try
                {
                    var v4 = ipProps.GetIPv4Properties();
                    if (v4 != null) info.DhcpEnabled = v4.IsDhcpEnabled;
                }
                catch { }

                try
                {
                    var gw = ipProps.GatewayAddresses?.FirstOrDefault()?.Address?.ToString();
                    if (!string.IsNullOrWhiteSpace(gw)) info.DefaultGateway = gw;

                    var dns = ipProps.DnsAddresses;
                    if (dns != null && dns.Count > 0) info.PrimaryDns = dns[0].ToString();
                    if (dns != null && dns.Count > 1) info.SecondaryDns = dns[1].ToString();
                }
                catch { }

                try
                {
                    var stats = nic.GetIPStatistics();
                    info.BytesSent = stats.BytesSent;
                    info.BytesReceived = stats.BytesReceived;
                    info.PacketsSent = stats.UnicastPacketsSent;
                    info.PacketsReceived = stats.UnicastPacketsReceived;
                }
                catch { }

                list.Add(info);
            }

            return new ObservableCollection<NetworkInterfaceInfo>(
                list.OrderBy(i => i.Priority)
                    .ThenBy(i => i.Name, StringComparer.OrdinalIgnoreCase));
        }

        private static string FormatMac(PhysicalAddress pa)
        {
            try
            {
                var bytes = pa?.GetAddressBytes();
                if (bytes == null || bytes.Length == 0) return string.Empty;
                return string.Join(":", bytes.Select(b => b.ToString("X2")));
            }
            catch
            {
                return string.Empty;
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    public class NetworkInterfaceInfo
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string OperationalStatus { get; set; } = string.Empty;
        public long SpeedMbps { get; set; }
        public string MacAddress { get; set; } = string.Empty;
        public int Priority { get; set; }
        public string IPv4Address { get; set; } = string.Empty;
        public string IPv4Mask { get; set; } = string.Empty;
        public bool DhcpEnabled { get; set; }
        public string DefaultGateway { get; set; } = string.Empty;
        public string IPv6Address { get; set; } = string.Empty;
        public string PrimaryDns { get; set; } = string.Empty;
        public string SecondaryDns { get; set; } = string.Empty;
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public long PacketsSent { get; set; }
        public long PacketsReceived { get; set; }
    }
}