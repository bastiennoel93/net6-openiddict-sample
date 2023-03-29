# .NET 6 Web API with OpenIddict

This is a sample .NET 6 Web API project that demonstrates how to integrate OpenIddict for authentication and authorization.

## Prerequisites
Before you get started, ensure that you have the following installed:

.NET 6 SDK

## Getting Started

Install the required packages:

```bash
dotnet restore
```
Build and run the project:

```bash
dotnet run
```
The API should now be running on https://localhost:5001.

## OpenIddict
This project uses OpenIddict for authentication and authorization. 

OpenIddict is a flexible and easy-to-use OpenID Connect and OAuth 2.0 server for .NET. 
It supports a wide range of OAuth 2.0 and OpenID Connect flows, including authorization code, client credentials, resource owner password credentials, and refresh token flows.

### Features
- Easy integration with ASP.NET Core 
- Support for both OAuth 2.0 and OpenID Connect protocols
- Support for multiple databases, including SQL Server, PostgreSQL, and MySQL
- Customizable token and authorization code format
- User-friendly error messages
- Comprehensive documentation and samples

### Configuration
1. Add the OpenIddict services to the DI container:
```csharp
services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        options.SetAccessTokenLifetime(TimeSpan.FromHours(1))
            .SetRefreshTokenLifetime(TimeSpan.FromDays(30))
            .AllowPasswordFlow()
            .AllowAuthorizationCodeFlow()
            .AllowRefreshTokenFlow()
            .AddEphemeralSigningKey();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
    });
```
2. Configure the OpenIddict middleware:
```csharp
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseOpenIddict();
```


## API Endpoints
This sample project includes the following API endpoints:


- POST /connect/token - Get an access token with the following parameters:
	- *grant_type=password*
	- *username=<your username>*
	- *password=<your password>*
	- *client_id=<client_id>*
	- *client_secret=<client_secret>*

The response will include an access token, which you can then use to access the API endpoints.

- GET /authorize - Return user identity name from access token


## License
This project is licensed under the [MIT](https://choosealicense.com/licenses/mit/) License.


## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.
