using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add Authentication + Authorization
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";       // Redirect unauthenticated users
        options.LogoutPath = "/logout";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.SlidingExpiration = true;   // Refresh cookie expiration on activity
        options.Cookie.HttpOnly = true;     // Prevent JavaScript access
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Use only over HTTPS
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Order matters: Authentication before Authorization
app.UseAuthentication();
app.UseAuthorization();

// Home page
app.MapGet("/", () => Results.Text($$"""
<html>
<body>
    <h1>Authentication Scheme: {{CookieAuthenticationDefaults.AuthenticationScheme}}</h1>
    <a href="/secret">/secret</a> requires authentication.
    <br/><br/>
    <form action="/login" method="post">
        <input type="text" name="username" placeholder="Enter username" required />
        <button type="submit">Login</button>
    </form>
    <form action="/logout" method="post">
        <button type="submit">Logout</button>
    </form>
</body>
</html>
""", "text/html"));

// Protected route
app.MapGet("/secret", (ClaimsPrincipal user) =>
    $"Hello {user.Identity?.Name}. This is a secret!")
    .RequireAuthorization();

// Login endpoint
app.MapPost("/login", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    var username = form["username"].ToString();

    // ✅ In real apps: validate user credentials from DB or identity system
    if (string.IsNullOrWhiteSpace(username))
        return Results.BadRequest("Username is required");

    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, username)
    };

    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var authProperties = new AuthenticationProperties
    {
        IsPersistent = true // Keeps cookie after browser close
    };

    await context.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(claimsIdentity),
        authProperties);

    return Results.Redirect("/");
});

// Logout endpoint
app.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/");
});

app.Run();
