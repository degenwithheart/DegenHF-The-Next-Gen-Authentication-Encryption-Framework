namespace DegenHF.NET_MAUI;

public partial class MainPage : ContentPage
{
    private readonly EccAuthHandler _authHandler;

    public MainPage()
    {
        InitializeComponent();

        // Get the auth handler from DI
        _authHandler = MauiApplication.Current.Services.GetService<EccAuthHandler>()
            ?? new EccAuthHandler();
    }

    private async void OnApiServerClicked(object sender, EventArgs e)
    {
        try
        {
            ApiServerButton.IsEnabled = false;
            StatusLabel.Text = "Starting API server...";

            // Start API server in background
            var apiServer = new ApiServer(_authHandler, LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<ApiServer>());
            _ = Task.Run(() => apiServer.StartAsync(Array.Empty<string>()));

            await Task.Delay(2000); // Wait a bit for server to start

            StatusLabel.Text = "API server started on https://localhost:5001";
            StatusLabel.TextColor = Colors.Green;
        }
        catch (Exception ex)
        {
            StatusLabel.Text = $"Failed to start API server: {ex.Message}";
            StatusLabel.TextColor = Colors.Red;
            ApiServerButton.IsEnabled = true;
        }
    }
}