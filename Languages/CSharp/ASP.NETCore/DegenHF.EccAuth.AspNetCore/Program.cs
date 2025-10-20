using DegenHF.EccAuth.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add ECC authentication
builder.Services.AddEccAuth();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Add ECC authentication middleware
app.UseEccAuth();

app.UseAuthorization();

app.MapControllers();

// Health check endpoint
app.MapGet("/health", () => new
{
    status = "healthy",
    service = "DegenHF-ASP.NET-Core"
});

app.Run();