using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;

// #nullable disable

namespace MbnDiagnostics
{
    // Converters for UI enhancements
    public class BooleanToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool b && b)
            {
                return Visibility.Visible;
            }
            return Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return DependencyProperty.UnsetValue;
        }
    }

    public class SignalQualityToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string quality)
            {
                return quality switch
                {
                    "Excellent" => new SolidColorBrush(Color.FromRgb(34, 197, 94)), // Green
                    "Good" => new SolidColorBrush(Color.FromRgb(52, 152, 219)), // Blue
                    "Fair" => new SolidColorBrush(Color.FromRgb(243, 156, 18)), // Orange
                    _ => new SolidColorBrush(Color.FromRgb(231, 76, 60)), // Red for Poor/Unknown
                };
            }
            return new SolidColorBrush(Colors.Red);
        }
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    public class EnumToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string status)
            {
                if (status.Equals("Connected", StringComparison.OrdinalIgnoreCase) || status.Contains("Ready", StringComparison.OrdinalIgnoreCase))
                {
                    return new SolidColorBrush(Color.FromRgb(34, 197, 94)); // Green
                }
                else if (status.Equals("Connecting", StringComparison.OrdinalIgnoreCase))
                {
                    return new SolidColorBrush(Color.FromRgb(52, 152, 219)); // Blue
                }
                else if (status.Equals("Disconnected", StringComparison.OrdinalIgnoreCase) || status.Equals("Not Initialized", StringComparison.OrdinalIgnoreCase))
                {
                    return new SolidColorBrush(Color.FromRgb(231, 76, 60)); // Red
                }
            }
            return new SolidColorBrush(Colors.White); // Default
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    // Data Models
    public class MbnInterface : INotifyPropertyChanged
    {
        // Basic Interface Info
        public string Name { get; set; }
        public string State { get; set; }
        public string Guid { get; set; }
        public string PhysicalAddress { get; set; }

        // Device Information
        public string Manufacturer { get; set; }
        public string Model { get; set; }
        public string Firmware { get; set; }
        public string DeviceId { get; set; }
        public string CellularClass { get; set; }
        public string DataClass { get; set; }
        public string VoiceClass { get; set; }
        public string SimClass { get; set; }
        public string SmsCapability { get; set; }
        public string ControlCapability { get; set; }
        public int MaxContexts { get; set; }

        // SIM and Subscriber Information
        public string SubscriberId { get; set; }
        public string SimIccId { get; set; }
        public string PhoneNumber { get; set; }
        public string ReadyState { get; set; }
        public bool EmergencyMode { get; set; }

        // Network and Provider Information
        public string Provider { get; set; }
        public string ProviderId { get; set; }
        public string RegisterState { get; set; }
        public string RegisterMode { get; set; }
        public bool IsRoaming { get; set; }

        // Signal Information
        public int SignalPercent { get; set; }
        public string SignalQuality { get; set; }
        public string RssiDbm { get; set; }
        public int RssiLevel { get; set; }
        public int ErrorRate { get; set; }
        public string HardwareRadio { get; set; }
        public string SoftwareRadio { get; set; }

        // Connection Information
        public string CurrentApn { get; set; }
        public bool IsConnected { get; set; }
        public bool LteAttached { get; set; }
        public bool AutoConnect { get; set; }
        public bool DataEnabled { get; set; }
        public string RoamControl { get; set; }
        public DateTime LastUpdated { get; set; }

        // Computed Properties
        public string DeviceInfo => $"{Manufacturer} {Model}";
        public string SignalDisplay => $"{SignalPercent}% ({SignalQuality})";
        public string RssiDisplay => string.IsNullOrEmpty(RssiDbm) ? "Unknown" : RssiDbm;
        public string DeviceIdentifiers => $"IMEI: {DeviceId}";
        public string SubscriberInfo => $"ID: {SubscriberId} | Phone: {PhoneNumber}";
        public string RadioStatus => $"HW: {HardwareRadio} | SW: {SoftwareRadio}";

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    public class ProvisionedContext
    {
        public int Id { get; set; }
        public string Type { get; set; }
        public string Apn { get; set; }
        public bool Enabled { get; set; }
        public string IpType { get; set; }
        public string Source { get; set; }
        public string DisplayName => $"{Type} - {Apn}";
        public string Status => Enabled ? "Enabled" : "Disabled";
    }

    public class NetworkProvider
    {
        public string Name { get; set; }
        public string Id { get; set; }
        public string State { get; set; }
        public string DataClass { get; set; }
        public bool IsHome { get; set; }
        public bool IsRegistered { get; set; }
    }

    public class PinInfo
    {
        public string PinType { get; set; }
        public string PinState { get; set; }
        public string PinMode { get; set; }
        public string PinFormat { get; set; }
        public int MinLength { get; set; }
        public int MaxLength { get; set; }
        public int AttemptsRemaining { get; set; }
    }

    public class SmsInfo
    {
        public bool ReadyToSend { get; set; }
        public string ServiceCenter { get; set; }
        public string SmsFormat { get; set; }
        public int AvailableMessages { get; set; }
        public string MessageStoreFull { get; set; }
    }

    // MBN Service
    public class MbnService
    {
        public async Task<string> RunCommandAsync(string arguments)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = arguments,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();

                return output;
            }
            catch (Exception ex)
            {
                return $"Error: {ex.Message}";
            }
        }

        public async Task<List<string>> GetInterfacesAsync()
        {
            var output = await RunCommandAsync("mbn show interfaces");
            var interfaces = new List<string>();

            var matches = Regex.Matches(output, @"Name\s*:\s*(.+)", RegexOptions.Multiline);
            foreach (Match match in matches)
            {
                interfaces.Add(match.Groups[1].Value.Trim());
            }

            return interfaces;
        }

        public async Task<MbnInterface> GetInterfaceDetailsAsync(string interfaceName)
        {
            var mbnInterface = new MbnInterface { Name = interfaceName };

            // Get interface info (basic details)
            var interfaceOutput = await RunCommandAsync("mbn show interfaces");
            ParseInterfaceInfo(interfaceOutput, mbnInterface);

            // Get device capabilities (IMEI, manufacturer, model, etc.)
            var capabilityOutput = await RunCommandAsync($"mbn show capability interface=\"{interfaceName}\"");
            ParseCapabilityInfo(capabilityOutput, mbnInterface);

            // Get ready info (SIM ID, Subscriber ID, phone number)
            var readyOutput = await RunCommandAsync($"mbn show readyinfo interface=\"{interfaceName}\"");
            ParseReadyInfo(readyOutput, mbnInterface);

            // Get connection info
            var connectionOutput = await RunCommandAsync($"mbn show connection interface=\"{interfaceName}\"");
            ParseConnectionInfo(connectionOutput, mbnInterface);

            // Get signal info
            var signalOutput = await RunCommandAsync($"mbn show signal interface=\"{interfaceName}\"");
            ParseSignalInfo(signalOutput, mbnInterface);

            // Get radio state
            var radioOutput = await RunCommandAsync($"mbn show radio interface=\"{interfaceName}\"");
            ParseRadioInfo(radioOutput, mbnInterface);

            // Get home provider info
            var providerOutput = await RunCommandAsync($"mbn show homeprovider interface=\"{interfaceName}\"");
            ParseHomeProviderInfo(providerOutput, mbnInterface);

            // Get auto connect state
            var acOutput = await RunCommandAsync($"mbn show acstate interface=\"{interfaceName}\"");
            mbnInterface.AutoConnect = acOutput.Contains("Auto connect token on");

            // Get data enablement
            var dataOutput = await RunCommandAsync($"mbn show dataenablement interface=\"{interfaceName}\"");
            mbnInterface.DataEnabled = dataOutput.Contains("Enabled");

            // Get roam control
            var roamOutput = await RunCommandAsync($"mbn show dataroamcontrol interface=\"{interfaceName}\"");
            ParseRoamControlInfo(roamOutput, mbnInterface);

            // Get LTE attach info
            var lteOutput = await RunCommandAsync($"mbn show netlteattachinfo interface=\"{interfaceName}\"");
            mbnInterface.LteAttached = lteOutput.Contains("Is LTE attached: 1");

            // Set signal quality based on percentage
            if (mbnInterface.SignalPercent >= 75) mbnInterface.SignalQuality = "Excellent";
            else if (mbnInterface.SignalPercent >= 50) mbnInterface.SignalQuality = "Good";
            else if (mbnInterface.SignalPercent >= 25) mbnInterface.SignalQuality = "Fair";
            else mbnInterface.SignalQuality = "Poor";

            mbnInterface.IsConnected = mbnInterface.State == "Connected";
            mbnInterface.LastUpdated = DateTime.Now;
            return mbnInterface;
        }

        public async Task<List<ProvisionedContext>> GetProvisionedContextsAsync(string interfaceName)
        {
            var output = await RunCommandAsync($"mbn show provisionedcontexts interface=\"{interfaceName}\"");
            var contexts = new List<ProvisionedContext>();

            var lines = output.Split('\n');
            ProvisionedContext currentContext = null;

            foreach (var line in lines)
            {
                var trimmed = line.Trim();

                if (trimmed.StartsWith("Serial number #"))
                {
                    if (currentContext != null && !string.IsNullOrEmpty(currentContext.Apn))
                        contexts.Add(currentContext);
                    currentContext = new ProvisionedContext();
                }
                else if (currentContext != null)
                {
                    if (trimmed.StartsWith("Context Id") && trimmed.Contains(":"))
                    {
                        var contextIdText = ExtractValue(trimmed);
                        if (int.TryParse(contextIdText, out int contextId))
                            currentContext.Id = contextId;
                    }
                    else if (trimmed.StartsWith("Context type"))
                        currentContext.Type = ExtractValue(trimmed);
                    else if (trimmed.StartsWith("Access Point Name"))
                        currentContext.Apn = ExtractValue(trimmed);
                    else if (trimmed.StartsWith("Context Enabled"))
                        currentContext.Enabled = ExtractValue(trimmed) == "Enabled";
                    else if (trimmed.StartsWith("IP type"))
                        currentContext.IpType = ExtractValue(trimmed);
                    else if (trimmed.StartsWith("Configuration Source"))
                        currentContext.Source = ExtractValue(trimmed);
                }
            }

            if (currentContext != null && !string.IsNullOrEmpty(currentContext.Apn))
                contexts.Add(currentContext);

            return contexts;
        }

        public async Task<List<NetworkProvider>> GetVisibleProvidersAsync(string interfaceName)
        {
            var output = await RunCommandAsync($"mbn show visibleproviders interface=\"{interfaceName}\"");
            var providers = new List<NetworkProvider>();

            var lines = output.Split('\n');
            NetworkProvider currentProvider = null;

            foreach (var line in lines)
            {
                var trimmed = line.Trim();

                if (trimmed.StartsWith("Provider #"))
                {
                    if (currentProvider != null)
                        providers.Add(currentProvider);
                    currentProvider = new NetworkProvider();
                }
                else if (currentProvider != null)
                {
                    if (trimmed.StartsWith("Name"))
                        currentProvider.Name = ExtractValue(trimmed);
                    else if (trimmed.StartsWith("Id"))
                        currentProvider.Id = ExtractValue(trimmed);
                    else if (trimmed.StartsWith("state"))
                    {
                        var state = ExtractValue(trimmed);
                        currentProvider.State = state;
                        currentProvider.IsHome = state.Contains("Home");
                        currentProvider.IsRegistered = state.Contains("Registered");
                    }
                    else if (trimmed.StartsWith("data class"))
                        currentProvider.DataClass = ExtractValue(trimmed);
                }
            }

            if (currentProvider != null)
                providers.Add(currentProvider);

            return providers;
        }

        public async Task<List<PinInfo>> GetPinInfoAsync(string interfaceName)
        {
            var output = await RunCommandAsync($"mbn show pinlist interface=\"{interfaceName}\"");
            var pins = new List<PinInfo>();

            var lines = output.Split('\n');
            PinInfo currentPin = null;

            foreach (var line in lines)
            {
                var trimmed = line.Trim();

                if (trimmed.StartsWith("Pin Type"))
                {
                    if (currentPin != null)
                        pins.Add(currentPin);
                    currentPin = new PinInfo { PinType = ExtractValue(trimmed) };
                }
                else if (currentPin != null)
                {
                    if (trimmed.StartsWith("Pin Mode"))
                        currentPin.PinMode = ExtractValue(trimmed);
                    else if (trimmed.StartsWith("Pin Format"))
                        currentPin.PinFormat = ExtractValue(trimmed);
                    else if (trimmed.StartsWith("Pin Minimum Length"))
                    {
                        var minLengthText = ExtractValue(trimmed);
                        if (int.TryParse(minLengthText, out int minLength))
                            currentPin.MinLength = minLength;
                    }
                    else if (trimmed.StartsWith("Pin Maximum Length"))
                    {
                        var maxLengthText = ExtractValue(trimmed);
                        if (int.TryParse(maxLengthText, out int maxLength))
                            currentPin.MaxLength = maxLength;
                    }
                }
            }

            if (currentPin != null)
                pins.Add(currentPin);

            // Get current PIN state
            var pinOutput = await RunCommandAsync($"mbn show pin interface=\"{interfaceName}\"");
            var currentPinState = ExtractValueFromPattern(pinOutput, @"Pin State\s*:\s*(.+)");
            var attemptsText = ExtractValueFromPattern(pinOutput, @"Attempts Remaining\s*:\s*(.+)");

            if (pins.Count > 0 && !string.IsNullOrEmpty(currentPinState))
            {
                pins[0].PinState = currentPinState;
                if (int.TryParse(attemptsText, out int attempts))
                    pins[0].AttemptsRemaining = attempts;
            }

            return pins;
        }

        public async Task<SmsInfo> GetSmsInfoAsync(string interfaceName)
        {
            var output = await RunCommandAsync($"mbn show smsconfig interface=\"{interfaceName}\"");
            var smsInfo = new SmsInfo();

            smsInfo.ReadyToSend = output.Contains("Ready to send SMS       : Yes");
            smsInfo.ServiceCenter = ExtractValueFromPattern(output, @"Service center address\s*:\s*(.+)");
            smsInfo.SmsFormat = ExtractValueFromPattern(output, @"SMS format\s*:\s*(.+)");
            smsInfo.MessageStoreFull = ExtractValueFromPattern(output, @"Message store full\s*:\s*(.+)");

            var messagesText = ExtractValueFromPattern(output, @"Available messages count\s*:\s*(.+)");
            if (int.TryParse(messagesText, out int messageCount))
                smsInfo.AvailableMessages = messageCount;

            return smsInfo;
        }

        private void ParseInterfaceInfo(string output, MbnInterface mbnInterface)
        {
            mbnInterface.Manufacturer = ExtractValueFromPattern(output, @"Manufacturer\s*:\s*(.+)");
            mbnInterface.Model = ExtractValueFromPattern(output, @"Model\s*:\s*(.+)");
            mbnInterface.Firmware = ExtractValueFromPattern(output, @"Firmware Version\s*:\s*(.+)");
            mbnInterface.Provider = ExtractValueFromPattern(output, @"Provider Name\s*:\s*(.+)");
            mbnInterface.State = ExtractValueFromPattern(output, @"State\s*:\s*(.+)");
            mbnInterface.DeviceId = ExtractValueFromPattern(output, @"Device Id\s*:\s*(.+)");
            mbnInterface.CellularClass = ExtractValueFromPattern(output, @"Cellular class\s*:\s*(.+)");
            mbnInterface.PhysicalAddress = ExtractValueFromPattern(output, @"Physical Address\s*:\s*(.+)");
            mbnInterface.Guid = ExtractValueFromPattern(output, @"GUID\s*:\s*(.+)");

            var roamingText = ExtractValueFromPattern(output, @"Roaming\s*:\s*(.+)");
            mbnInterface.IsRoaming = !roamingText.Contains("Not roaming");

            var signalMatch = Regex.Match(output, @"Signal\s*:\s*(\d+)%");
            if (signalMatch.Success)
            {
                mbnInterface.SignalPercent = int.Parse(signalMatch.Groups[1].Value);
            }

            var rssiMatch = Regex.Match(output, @"RSSI / RSCP\s*:\s*(\d+)\s*\(([^)]+)\)");
            if (rssiMatch.Success)
            {
                mbnInterface.RssiLevel = int.Parse(rssiMatch.Groups[1].Value);
                mbnInterface.RssiDbm = rssiMatch.Groups[2].Value;
            }
        }

        private void ParseCapabilityInfo(string output, MbnInterface mbnInterface)
        {
            if (string.IsNullOrEmpty(mbnInterface.Manufacturer))
                mbnInterface.Manufacturer = ExtractValueFromPattern(output, @"Manufacturer\s*:\s*(.+)");
            if (string.IsNullOrEmpty(mbnInterface.Model))
                mbnInterface.Model = ExtractValueFromPattern(output, @"Model\s*:\s*(.+)");
            if (string.IsNullOrEmpty(mbnInterface.Firmware))
                mbnInterface.Firmware = ExtractValueFromPattern(output, @"Firmware Information\s*:\s*(.+)");
            if (string.IsNullOrEmpty(mbnInterface.DeviceId))
                mbnInterface.DeviceId = ExtractValueFromPattern(output, @"Device Id\s*:\s*(.+)");
            if (string.IsNullOrEmpty(mbnInterface.CellularClass))
                mbnInterface.CellularClass = ExtractValueFromPattern(output, @"Cellular class\s*:\s*(.+)");

            mbnInterface.DataClass = ExtractValueFromPattern(output, @"Data class\s*:\s*(.+)");
            mbnInterface.VoiceClass = ExtractValueFromPattern(output, @"Voice class\s*:\s*(.+)");
            mbnInterface.SimClass = ExtractValueFromPattern(output, @"Sim class\s*:\s*(.+)");
            mbnInterface.SmsCapability = ExtractValueFromPattern(output, @"SMS capability\s*:\s*(.+)");
            mbnInterface.ControlCapability = ExtractValueFromPattern(output, @"Control capability\s*:\s*(.+)");

            var maxContextsText = ExtractValueFromPattern(output, @"Maximum activation contexts\s*:\s*(.+)");
            if (int.TryParse(maxContextsText, out int maxContexts))
            {
                mbnInterface.MaxContexts = maxContexts;
            }
        }

        private void ParseReadyInfo(string output, MbnInterface mbnInterface)
        {
            mbnInterface.ReadyState = ExtractValueFromPattern(output, @"State\s*:\s*(.+)");
            mbnInterface.SubscriberId = ExtractValueFromPattern(output, @"Subscriber Id\s*:\s*(.+)");
            mbnInterface.SimIccId = ExtractValueFromPattern(output, @"SIM ICC Id\s*:\s*(.+)");

            var emergencyText = ExtractValueFromPattern(output, @"Emergency mode\s*:\s*(.+)");
            mbnInterface.EmergencyMode = emergencyText.Contains("On");

            var phoneMatch = Regex.Match(output, @"Telephone #\d+\s*:\s*(.+)");
            if (phoneMatch.Success)
            {
                var phone = phoneMatch.Groups[1].Value.Trim();
                mbnInterface.PhoneNumber = phone == "?" ? "Not Available" : phone;
            }
        }

        private void ParseConnectionInfo(string output, MbnInterface mbnInterface)
        {
            if (string.IsNullOrEmpty(mbnInterface.State))
                mbnInterface.State = ExtractValueFromPattern(output, @"Interface State\s*:\s*(.+)");

            mbnInterface.RegisterState = ExtractValueFromPattern(output, @"Register State\s*:\s*(.+)");
            mbnInterface.RegisterMode = ExtractValueFromPattern(output, @"Register Mode\s*:\s*(.+)");

            if (string.IsNullOrEmpty(mbnInterface.Provider))
                mbnInterface.Provider = ExtractValueFromPattern(output, @"Provider Name\s*:\s*(.+)");

            mbnInterface.ProviderId = ExtractValueFromPattern(output, @"Provider Id\s*:\s*(.+)");

            if (string.IsNullOrEmpty(mbnInterface.DataClass))
                mbnInterface.DataClass = ExtractValueFromPattern(output, @"Provider Data Class\s*:\s*(.+)");

            mbnInterface.CurrentApn = ExtractValueFromPattern(output, @"Access Point Name\s*:\s*(.+)");
        }

        private void ParseSignalInfo(string output, MbnInterface mbnInterface)
        {
            var signalMatch = Regex.Match(output, @"Signal\s*:\s*(\d+)%");
            if (signalMatch.Success)
            {
                mbnInterface.SignalPercent = int.Parse(signalMatch.Groups[1].Value);
            }

            var rssiMatch = Regex.Match(output, @"RSSI / RSCP\s*:\s*(\d+)\s*\(([^)]+)\)");
            if (rssiMatch.Success)
            {
                mbnInterface.RssiLevel = int.Parse(rssiMatch.Groups[1].Value);
                mbnInterface.RssiDbm = rssiMatch.Groups[2].Value;
            }

            var errorRateText = ExtractValueFromPattern(output, @"Error Rate\s*:\s*(.+)");
            if (int.TryParse(errorRateText, out int errorRate))
            {
                mbnInterface.ErrorRate = errorRate;
            }
        }

        private void ParseRadioInfo(string output, MbnInterface mbnInterface)
        {
            mbnInterface.HardwareRadio = ExtractValueFromPattern(output, @"Hardware radio state\s*:\s*(.+)");
            mbnInterface.SoftwareRadio = ExtractValueFromPattern(output, @"Software radio state\s*:\s*(.+)");
        }

        private void ParseHomeProviderInfo(string output, MbnInterface mbnInterface)
        {
            if (string.IsNullOrEmpty(mbnInterface.Provider))
                mbnInterface.Provider = ExtractValueFromPattern(output, @"Home provider name\s*:\s*(.+)");
            if (string.IsNullOrEmpty(mbnInterface.ProviderId))
                mbnInterface.ProviderId = ExtractValueFromPattern(output, @"Home provider Id\s*:\s*(.+)");
        }

        private void ParseRoamControlInfo(string output, MbnInterface mbnInterface)
        {
            mbnInterface.RoamControl = ExtractValueFromPattern(output, @"Internet Always On\s*:\s*(.+)");
        }

        private string ExtractValueFromPattern(string text, string pattern)
        {
            var match = Regex.Match(text, pattern);
            return match.Success ? match.Groups[1].Value.Trim() : "";
        }

        private string ExtractValue(string line)
        {
            var index = line.IndexOf(':');
            return index >= 0 ? line.Substring(index + 1).Trim() : "";
        }
    }

    // Main Window
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        private readonly MbnService _mbnService;
        private readonly DispatcherTimer _refreshTimer;
        private MbnInterface _currentInterface;
        private ObservableCollection<ProvisionedContext> _contexts;
        private ObservableCollection<NetworkProvider> _providers;
        private ObservableCollection<PinInfo> _pinInfo;
        private SmsInfo _smsInfo;
        private bool _isLoading;

        public MbnInterface CurrentInterface
        {
            get => _currentInterface;
            set { _currentInterface = value; OnPropertyChanged(); }
        }

        public ObservableCollection<ProvisionedContext> Contexts
        {
            get => _contexts;
            set { _contexts = value; OnPropertyChanged(); }
        }

        public ObservableCollection<NetworkProvider> Providers
        {
            get => _providers;
            set { _providers = value; OnPropertyChanged(); }
        }

        public ObservableCollection<PinInfo> PinInfo
        {
            get => _pinInfo;
            set { _pinInfo = value; OnPropertyChanged(); }
        }

        public SmsInfo SmsInfo
        {
            get => _smsInfo;
            set { _smsInfo = value; OnPropertyChanged(); }
        }

        public bool IsLoading
        {
            get => _isLoading;
            set
            {
                _isLoading = value;
                OnPropertyChanged();
                if (RefreshButton != null)
                    RefreshButton.IsEnabled = !value;
                if (TcpIpButton != null)
                    TcpIpButton.IsEnabled = !value;
            }
        }

        public MainWindow()
        {
            InitializeComponent();
            DataContext = this;

            _mbnService = new MbnService();
            _refreshTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(30)
            };
            _refreshTimer.Tick += async (s, e) => await RefreshDataAsync();

            Loaded += async (s, e) => await InitializeAsync();
        }

        private async Task InitializeAsync()
        {
            IsLoading = true;

            try
            {
                var interfaces = await _mbnService.GetInterfacesAsync();
                if (interfaces.Any())
                {
                    await LoadInterfaceDataAsync(interfaces.First());
                    _refreshTimer.Start();
                }
                else
                {
                    MessageBox.Show("No Mobile Broadband interfaces found.", "MBN Diagnostics",
                                  MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error initializing: {ex.Message}", "Error",
                              MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                IsLoading = false;
            }
        }

        private async Task LoadInterfaceDataAsync(string interfaceName)
        {
            CurrentInterface = await _mbnService.GetInterfaceDetailsAsync(interfaceName);
            Contexts = new ObservableCollection<ProvisionedContext>(
                await _mbnService.GetProvisionedContextsAsync(interfaceName));
            Providers = new ObservableCollection<NetworkProvider>(
                await _mbnService.GetVisibleProvidersAsync(interfaceName));
            PinInfo = new ObservableCollection<PinInfo>(
                await _mbnService.GetPinInfoAsync(interfaceName));
            SmsInfo = await _mbnService.GetSmsInfoAsync(interfaceName);
        }

        private async Task RefreshDataAsync()
        {
            if (CurrentInterface != null && !IsLoading)
            {
                IsLoading = true;
                try
                {
                    await LoadInterfaceDataAsync(CurrentInterface.Name);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Refresh error: {ex.Message}");
                }
                finally
                {
                    IsLoading = false;
                }
            }
        }

        private async void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            await RefreshDataAsync();
        }

        private void TcpIpButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var tcpIpWindow = new TcpIpWindow
                {
                    Owner = this
                };
                tcpIpWindow.Show();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error opening TCP/IP window: {ex.Message}", "Error",
                              MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }
}