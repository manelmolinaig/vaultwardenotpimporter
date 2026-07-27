using System.ComponentModel;
using VaultwardenOtpImporter.Models;
using VaultwardenOtpImporter.Services;

namespace VaultwardenOtpImporter;

public sealed class MainForm : Form
{
    private readonly TextBox _emailTextBox = new();
    private readonly TextBox _passwordTextBox = new();
    private readonly TextBox _serverTextBox = new();
    private readonly TextBox _imagePathTextBox = new();
    private readonly PictureBox _previewPictureBox = new();
    private readonly Button _browseButton = new();
    private readonly Button _importButton = new();
    private readonly Button _transferButton = new();
    private readonly DataGridView _otpGrid = new();
    private readonly DataGridView _accountsGrid = new();
    private readonly Label _statusLabel = new();
    private readonly BindingList<OtpEntry> _otpEntries = [];
    private readonly BindingList<VaultAccount> _vaultAccounts = [];
    private readonly GoogleAuthenticatorDecoder _decoder = new();
    private readonly BitwardenCliService _vaultService = new();
    private readonly CancellationTokenSource _closingTokenSource = new();

    public MainForm()
    {
        Text = "Importador OTP para Vaultwarden";
        Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        MinimumSize = new Size(1180, 680);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9F);
        BuildInterface();
    }

    private void BuildInterface()
    {
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(12),
            ColumnCount = 3,
            RowCount = 2
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 35));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 35));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        Controls.Add(root);

        root.Controls.Add(BuildConnectionPanel(), 0, 0);
        root.Controls.Add(BuildOtpPanel(), 1, 0);
        root.Controls.Add(BuildAccountsPanel(), 2, 0);

        _statusLabel.Text = "Selecciona una imagen QR para comenzar.";
        _statusLabel.AutoSize = true;
        _statusLabel.Padding = new Padding(0, 8, 0, 0);
        root.Controls.Add(_statusLabel, 0, 1);
        root.SetColumnSpan(_statusLabel, 3);

        FormClosing += MainForm_FormClosing;
    }

    private Control BuildConnectionPanel()
    {
        var group = CreateGroup("Conexión e imagen");
        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(10),
            ColumnCount = 1,
            RowCount = 9
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (var row = 0; row < 8; row++)
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        group.Controls.Add(layout);

        AddLabel(layout, "Servidor de Vaultwarden", 0);
        _serverTextBox.PlaceholderText = "https://vault.example.com";
        AddControl(layout, _serverTextBox, 1);

        AddLabel(layout, "Correo electrónico", 2);
        AddControl(layout, _emailTextBox, 3);

        AddLabel(layout, "Contraseña maestra", 4);
        _passwordTextBox.UseSystemPasswordChar = true;
        AddControl(layout, _passwordTextBox, 5);

        AddLabel(layout, "Imagen con el QR", 6);
        var imageSelector = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 2,
            Margin = new Padding(0, 0, 0, 6)
        };
        imageSelector.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        imageSelector.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        _imagePathTextBox.ReadOnly = true;
        _imagePathTextBox.Dock = DockStyle.Fill;
        imageSelector.Controls.Add(_imagePathTextBox, 0, 0);
        _browseButton.Text = "Examinar…";
        _browseButton.AutoSize = true;
        _browseButton.Click += BrowseButton_Click;
        imageSelector.Controls.Add(_browseButton, 1, 0);
        layout.Controls.Add(imageSelector, 0, 7);

        var lowerPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            RowCount = 3,
            ColumnCount = 1
        };
        lowerPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        lowerPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        lowerPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        _previewPictureBox.Dock = DockStyle.Fill;
        _previewPictureBox.BorderStyle = BorderStyle.FixedSingle;
        _previewPictureBox.BackColor = Color.WhiteSmoke;
        _previewPictureBox.SizeMode = PictureBoxSizeMode.Zoom;
        lowerPanel.Controls.Add(_previewPictureBox, 0, 0);

        _importButton.Text = "Importar";
        _importButton.Dock = DockStyle.Fill;
        _importButton.AutoSize = true;
        _importButton.MinimumSize = new Size(0, 40);
        _importButton.Padding = new Padding(0, 7, 0, 7);
        _importButton.Click += ImportButton_Click;
        lowerPanel.Controls.Add(_importButton, 0, 1);

        _transferButton.Text = "Transferir";
        _transferButton.Dock = DockStyle.Fill;
        _transferButton.AutoSize = true;
        _transferButton.MinimumSize = new Size(0, 40);
        _transferButton.Margin = new Padding(0, 6, 0, 0);
        _transferButton.Padding = new Padding(0, 7, 0, 7);
        _transferButton.Click += TransferButton_Click;
        lowerPanel.Controls.Add(_transferButton, 0, 2);

        layout.Controls.Add(lowerPanel, 0, 8);
        return group;
    }

    private Control BuildOtpPanel()
    {
        var group = CreateGroup("OTP encontrados");
        ConfigureGrid(_otpGrid);
        _otpGrid.AutoGenerateColumns = false;
        _otpGrid.Columns.Add(TextColumn("Emisor", nameof(OtpEntry.DisplayIssuer), 120));
        _otpGrid.Columns.Add(TextColumn("Cuenta", nameof(OtpEntry.Account), 180));
        _otpGrid.Columns.Add(TextColumn("Algoritmo", nameof(OtpEntry.Algorithm), 80));
        _otpGrid.Columns.Add(TextColumn("Dígitos", nameof(OtpEntry.Digits), 55));
        _otpGrid.DataSource = _otpEntries;
        group.Controls.Add(_otpGrid);
        return group;
    }

    private Control BuildAccountsPanel()
    {
        var group = CreateGroup("Cuentas de Vaultwarden");
        ConfigureGrid(_accountsGrid);
        _accountsGrid.AutoGenerateColumns = false;
        _accountsGrid.Columns.Add(TextColumn("Nombre", nameof(VaultAccount.Name), 170));
        _accountsGrid.Columns.Add(TextColumn("Usuario", nameof(VaultAccount.Username), 180));
        _accountsGrid.Columns.Add(TextColumn("Tiene OTP", nameof(VaultAccount.OtpStatus), 70));
        _accountsGrid.DataSource = _vaultAccounts;
        group.Controls.Add(_accountsGrid);
        return group;
    }

    private static GroupBox CreateGroup(string title) => new()
    {
        Text = title,
        Dock = DockStyle.Fill,
        Padding = new Padding(8)
    };

    private static void ConfigureGrid(DataGridView grid)
    {
        grid.Dock = DockStyle.Fill;
        grid.ReadOnly = true;
        grid.MultiSelect = false;
        grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        grid.AllowUserToAddRows = false;
        grid.AllowUserToDeleteRows = false;
        grid.AllowUserToResizeRows = false;
        grid.RowHeadersVisible = false;
        grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
    }

    private static DataGridViewTextBoxColumn TextColumn(string title, string property, int minimumWidth) => new()
    {
        HeaderText = title,
        DataPropertyName = property,
        MinimumWidth = minimumWidth,
        SortMode = DataGridViewColumnSortMode.Automatic
    };

    private static void AddLabel(TableLayoutPanel layout, string text, int row)
    {
        var label = new Label
        {
            Text = text,
            AutoSize = true,
            Margin = new Padding(0, row == 0 ? 0 : 7, 0, 2)
        };
        layout.Controls.Add(label, 0, row);
    }

    private static void AddControl(TableLayoutPanel layout, Control control, int row)
    {
        control.Dock = DockStyle.Fill;
        control.Margin = new Padding(0);
        layout.Controls.Add(control, 0, row);
    }

    private void BrowseButton_Click(object? sender, EventArgs e)
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Selecciona la imagen con el QR",
            Filter = "Imágenes|*.png;*.jpg;*.jpeg;*.bmp;*.gif|Todos los archivos|*.*",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;

        _imagePathTextBox.Text = dialog.FileName;
        var oldImage = _previewPictureBox.Image;
        using var source = Image.FromFile(dialog.FileName);
        _previewPictureBox.Image = new Bitmap(source);
        oldImage?.Dispose();
        _statusLabel.Text = "Imagen seleccionada. Pulsa Importar para cargar los datos.";
    }

    private async void ImportButton_Click(object? sender, EventArgs e)
    {
        if (!ValidateImportFields()) return;
        await RunBusyAsync("Leyendo QR y conectando con Vaultwarden…", async token =>
        {
            var decodeTask = Task.Run(
                () => _decoder.DecodeImage(_imagePathTextBox.Text),
                token);
            var accountsTask = _vaultService.ConnectAndLoadAsync(
                _serverTextBox.Text.Trim(),
                _emailTextBox.Text.Trim(),
                _passwordTextBox.Text,
                token);
            await Task.WhenAll(decodeTask, accountsTask);
            var decoded = await decodeTask;
            var accounts = await accountsTask;

            _otpEntries.Clear();
            foreach (var entry in decoded) _otpEntries.Add(entry);
            _vaultAccounts.Clear();
            foreach (var account in accounts) _vaultAccounts.Add(account);
            _statusLabel.Text = $"{decoded.Count} OTP y {accounts.Count} cuentas cargadas.";
        });
    }

    private async void TransferButton_Click(object? sender, EventArgs e)
    {
        if (_otpGrid.SelectedRows.Count != 1 || _accountsGrid.SelectedRows.Count != 1)
        {
            MessageBox.Show(
                this,
                "Selecciona exactamente un OTP y una cuenta de Vaultwarden.",
                "Selección necesaria",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        var otp = _otpGrid.SelectedRows[0].DataBoundItem as OtpEntry;
        var account = _accountsGrid.SelectedRows[0].DataBoundItem as VaultAccount;
        if (otp is null || account is null)
        {
            MessageBox.Show(this, "La selección no es válida.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        if (!string.IsNullOrWhiteSpace(account.Login?.Totp))
        {
            var answer = MessageBox.Show(
                this,
                $"La cuenta «{account.Name}» ya tiene un OTP. ¿Quieres sobrescribirlo?",
                "Sobrescribir OTP",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);
            if (answer != DialogResult.Yes) return;
        }

        await RunBusyAsync("Transfiriendo OTP…", async token =>
        {
            var progress = new Progress<string>(message => _statusLabel.Text = message);
            await _vaultService.TransferTotpAsync(account, otp, progress, token);
            var position = _vaultAccounts.IndexOf(account);
            if (position >= 0)
            {
                _vaultAccounts[position] = new VaultAccount
                {
                    Id = account.Id,
                    Name = account.Name,
                    Login = new VaultLogin { Username = account.Username, Totp = otp.ToOtpAuthUri() },
                    RawJson = account.RawJson
                };
            }
            _statusLabel.Text = $"OTP transferido a «{account.Name}».";
            MessageBox.Show(
                this,
                "El OTP se ha transferido correctamente.",
                "Transferencia completada",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        });
    }

    private bool ValidateImportFields()
    {
        if (string.IsNullOrWhiteSpace(_serverTextBox.Text) ||
            string.IsNullOrWhiteSpace(_emailTextBox.Text) ||
            string.IsNullOrEmpty(_passwordTextBox.Text) ||
            string.IsNullOrWhiteSpace(_imagePathTextBox.Text))
        {
            MessageBox.Show(
                this,
                "Completa servidor, correo, contraseña y selecciona una imagen QR.",
                "Datos incompletos",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return false;
        }
        return true;
    }

    private async Task RunBusyAsync(string status, Func<CancellationToken, Task> action)
    {
        SetBusy(true);
        _statusLabel.Text = status;
        try
        {
            await action(_closingTokenSource.Token);
        }
        catch (OperationCanceledException) when (_closingTokenSource.IsCancellationRequested) { }
        catch (Exception exception)
        {
            _statusLabel.Text = "La operación no se ha completado.";
            MessageBox.Show(this, exception.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void SetBusy(bool busy)
    {
        UseWaitCursor = busy;
        _browseButton.Enabled = !busy;
        _importButton.Enabled = !busy;
        _transferButton.Enabled = !busy;
    }

    private async void MainForm_FormClosing(object? sender, FormClosingEventArgs e)
    {
        _closingTokenSource.Cancel();
        try { await _vaultService.LogoutAsync(); } catch { }
        _previewPictureBox.Image?.Dispose();
        _vaultService.Dispose();
        _closingTokenSource.Dispose();
    }
}
