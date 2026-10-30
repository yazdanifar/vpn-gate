using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using VPNGate.Core;

namespace VPNGate.App;

/// <summary>The "VPN Connection Setting" editor sheet (UI-SPEC 6).</summary>
internal static class AccountEditor
{
    /// <summary>Returns true when the setting was saved.</summary>
    public static async Task<bool> ShowAsync(Window owner, XamlRoot root, MainViewModel vm, ClientAccount? existing)
    {
        var accounts = vm.Accounts;
        if (accounts is null) return false;
        var state = existing is null
            ? new AccountEditorState()
            : new AccountEditorState(existing, accounts.Password(existing), accounts.HasCertificateIdentity(existing));

        var dialog = new ContentDialog
        {
            XamlRoot = root,
            Title = existing is null ? "New VPN Connection Setting" : "Edit VPN Connection Setting",
            PrimaryButtonText = "Save",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
        };
        dialog.Resources["ContentDialogMaxWidth"] = 720.0;

        var form = new StackPanel { Spacing = 6, MinWidth = 480 };
        var hostError = Ui.Error(null);
        var fpError = Ui.Error(null);
        var mtuError = Ui.Error(null);
        var macError = Ui.Error(null);
        var advancedHint = Ui.Error(null);
        var certStatus = Ui.Caption("");
        var certError = Ui.Error(null);

        void Revalidate()
        {
            dialog.IsPrimaryButtonEnabled = state.CanSave;
            Ui.SetError(hostError, state.Host.Trim().Length == 0 || InputValidation.IsValidHost(state.Host.Trim()) ? null : "Not a valid host name or IP address.");
            Ui.SetError(fpError, state.FingerprintError);
            Ui.SetError(mtuError, state.MtuError);
            Ui.SetError(macError, state.MacError);
            Ui.SetError(advancedHint, state.AdvancedInvalid ? "Something in the Advanced Options needs fixing before you can save." : null);
            Ui.SetError(certError, state.ImportError);
            certStatus.Text = state.CertDer is not null && state.PrivateKeyDer is not null
                ? "Certificate and RSA key ready to save."
                : state.HasStoredIdentity
                    ? "A certificate and key are stored in Credential Manager. Import again to replace them."
                    : "No certificate yet. Import a PEM/DER certificate with its RSA key, or a .p12 file.";
        }

        TextBox Box(string value, Action<string> set, string? placeholder = null, double width = 360)
        {
            var b = new TextBox { Text = value, PlaceholderText = placeholder ?? "", Width = width, HorizontalAlignment = HorizontalAlignment.Left };
            b.TextChanged += (_, _) => { set(b.Text); Revalidate(); };
            return b;
        }

        NumberBox Num(double value, double min, double max, Action<int> set)
        {
            var n = new NumberBox { Value = value, Minimum = min, Maximum = max, SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Compact, Width = 140, HorizontalAlignment = HorizontalAlignment.Left };
            n.ValueChanged += (_, e) => { if (!double.IsNaN(e.NewValue)) set((int)e.NewValue); Revalidate(); };
            return n;
        }

        ToggleSwitch Toggle(string header, bool on, Action<bool> set)
        {
            var t = new ToggleSwitch { Header = header, IsOn = on };
            t.Toggled += (_, _) => { set(t.IsOn); Revalidate(); };
            return t;
        }

        // General Setting
        form.Children.Add(Ui.Header("General Setting"));
        form.Children.Add(new TextBlock { Text = "Setting Name:" });
        form.Children.Add(Box(state.Name, v => state.Name = v));

        // Destination VPN Server
        form.Children.Add(Ui.Header("Destination VPN Server"));
        form.Children.Add(new TextBlock { Text = "Host Name / IP Address:" });
        form.Children.Add(Box(state.Host, v => state.Host = v));
        form.Children.Add(hostError);
        form.Children.Add(new TextBlock { Text = "Port Number (comma separated):" });
        form.Children.Add(Box(state.PortString, v => state.PortString = v));
        form.Children.Add(new TextBlock { Text = "Virtual HUB Name:" });
        form.Children.Add(Box(state.Hub, v => state.Hub = v));

        // User Authentication Setting
        form.Children.Add(Ui.Header("User Authentication Setting"));
        var auth = new ComboBox { Width = 360 };
        foreach (var t in AuthTypes.All) auth.Items.Add(t);
        auth.SelectedItem = state.AuthType;
        form.Children.Add(new TextBlock { Text = "Auth Type:" });
        form.Children.Add(auth);
        form.Children.Add(new TextBlock { Text = "User Name:" });
        form.Children.Add(Box(state.Username, v => state.Username = v));

        var passwordPanel = new StackPanel { Spacing = 6 };
        passwordPanel.Children.Add(new TextBlock { Text = "Password:" });
        var password = new PasswordBox { Password = state.Password, Width = 360, HorizontalAlignment = HorizontalAlignment.Left };
        password.PasswordChanged += (_, _) => state.Password = password.Password;
        passwordPanel.Children.Add(password);
        form.Children.Add(passwordPanel);

        var certPanel = new StackPanel { Spacing = 6 };
        certPanel.Children.Add(certStatus);
        var pem = new Button { Content = "Certificate + Key (PEM/DER)…" };
        pem.Click += async (_, _) =>
        {
            var cert = await Ui.PickFileAsync(owner, "Choose the certificate (PEM or DER)", ".pem", ".crt", ".cer", ".der");
            if (cert is null) return;
            var key = await Ui.PickFileAsync(owner, "Choose its RSA private key (PEM or DER, not passphrase-protected)", ".pem", ".key", ".der");
            if (key is null) return;
            try
            {
                var id = CertImport.Pair(CertImport.ParseCertificate(cert), CertImport.ParsePrivateKey(key));
                (state.CertDer, state.PrivateKeyDer, state.ImportError) = (id.CertDer, id.PrivateKeyDer, null);
            }
            catch (Exception e) when (e is CertImportException or System.Security.Cryptography.CryptographicException)
            {
                state.ImportError = e.Message;
            }
            Revalidate();
        };
        var pass = new PasswordBox { Width = 240, PlaceholderText = "Passphrase for the .p12 file" };
        var p12 = new Button { Content = "PKCS#12 (.p12)…" };
        p12.Click += async (_, _) =>
        {
            var data = await Ui.PickFileAsync(owner, "Choose the PKCS#12 file (.p12 / .pfx)", ".p12", ".pfx");
            if (data is null) return;
            try
            {
                var id = CertImport.ParsePkcs12(data, pass.Password);
                (state.CertDer, state.PrivateKeyDer, state.ImportError) = (id.CertDer, id.PrivateKeyDer, null);
            }
            catch (CertImportException e)
            {
                state.ImportError = e.Message;
            }
            Revalidate();
        };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        buttons.Children.Add(pem);
        buttons.Children.Add(p12);
        certPanel.Children.Add(buttons);
        certPanel.Children.Add(new TextBlock { Text = "Passphrase for the .p12 file:" });
        certPanel.Children.Add(pass);
        certPanel.Children.Add(certError);
        form.Children.Add(certPanel);

        void ShowAuthFields()
        {
            passwordPanel.Visibility = AuthTypes.UsesPassword(state.AuthType) ? Visibility.Visible : Visibility.Collapsed;
            certPanel.Visibility = state.AuthType == AuthTypes.Certificate ? Visibility.Visible : Visibility.Collapsed;
        }
        auth.SelectionChanged += (_, _) =>
        {
            if (auth.SelectedItem is string s) state.AuthType = s;
            ShowAuthFields();
            Revalidate();
        };

        // Advanced Options
        var adv = new StackPanel { Spacing = 6 };
        adv.Children.Add(new TextBlock { Text = "Max TCP Connections (1–32):" });
        adv.Children.Add(Num(state.MaxConnection, 1, 32, v => state.MaxConnection = v));
        adv.Children.Add(Toggle("Use Data Compression", state.Compression, v => state.Compression = v));
        adv.Children.Add(Toggle("Use UDP Acceleration (Fastest)", state.UdpAcceleration, v => state.UdpAcceleration = v));
        adv.Children.Add(Toggle("Use QoS", state.UseQoS, v => state.UseQoS = v));
        adv.Children.Add(Toggle("Use Half Connection (separate send/receive sockets)", state.HalfConnection, v => state.HalfConnection = v));
        adv.Children.Add(new TextBlock { Text = "MTU (blank = automatic):" });
        adv.Children.Add(Box(state.MtuString, v => state.MtuString = v, width: 140));
        adv.Children.Add(mtuError);
        adv.Children.Add(new TextBlock { Text = "Virtual MAC address (blank = random):" });
        adv.Children.Add(Box(state.MacString, v => state.MacString = v, "00:AC:DE:12:34:56", 240));
        adv.Children.Add(macError);
        adv.Children.Add(Toggle("Verify Server Certificate", state.CheckServerCert, v => state.CheckServerCert = v));
        adv.Children.Add(new TextBlock { Text = "Server certificate fingerprint (SHA-1 / SHA-256, optional):" });
        adv.Children.Add(Box(state.Fingerprint, v => state.Fingerprint = v));
        adv.Children.Add(fpError);
        adv.Children.Add(Ui.Caption("A fingerprint is enforced whenever it is set. Without one, “Verify Server Certificate” uses the system trust store."));
        var retry = new StackPanel { Spacing = 6 };
        retry.Children.Add(new TextBlock { Text = "Retry every (s, 1–300):" });
        retry.Children.Add(Num(state.ReconnectIntervalSeconds, 1, 300, v => state.ReconnectIntervalSeconds = v));
        retry.Children.Add(new TextBlock { Text = "Give up after (attempts, 1–1000):" });
        retry.Children.Add(Num(state.ReconnectCount, 1, 1000, v => state.ReconnectCount = v));
        retry.Visibility = state.AutoReconnect ? Visibility.Visible : Visibility.Collapsed;
        adv.Children.Add(Toggle("Auto Reconnect on disconnect", state.AutoReconnect, v =>
        {
            state.AutoReconnect = v;
            retry.Visibility = v ? Visibility.Visible : Visibility.Collapsed;
        }));
        adv.Children.Add(retry);
        form.Children.Add(new Expander
        {
            Header = "Advanced Options",
            Content = adv,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            Margin = new Thickness(0, 12, 0, 0),
        });
        form.Children.Add(advancedHint);

        // Routing
        form.Children.Add(Ui.Header("Routing"));
        var routingHost = new StackPanel();
        var routingCaption = Ui.Caption("Uses the app's global routing rules (Settings → Routing).");
        var routingEditor = new RoutingEditor(state.Routing, () => { }, () => dialog.XamlRoot);
        void ShowRouting()
        {
            routingEditor.Visibility = state.UseCustomRouting ? Visibility.Visible : Visibility.Collapsed;
            routingCaption.Visibility = state.UseCustomRouting ? Visibility.Collapsed : Visibility.Visible;
        }
        form.Children.Add(Toggle("Use custom routing rules for this connection", state.UseCustomRouting, v =>
        {
            state.UseCustomRouting = v;
            ShowRouting();
        }));
        routingHost.Children.Add(routingCaption);
        routingHost.Children.Add(routingEditor);
        form.Children.Add(routingHost);
        ShowRouting();
        ShowAuthFields();
        Revalidate();

        dialog.Content = new ScrollViewer { Content = form, MaxHeight = 560, Padding = new Thickness(0, 0, 16, 0) };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return false;

        var account = state.MakeAccount(existing);
        var pw = AuthTypes.UsesPassword(account.AuthType) ? state.Password : null;
        if (existing is null) accounts.Add(account, pw, state.CertDer, state.PrivateKeyDer);
        else accounts.Update(account, pw, state.CertDer, state.PrivateKeyDer);
        return true;
    }
}
