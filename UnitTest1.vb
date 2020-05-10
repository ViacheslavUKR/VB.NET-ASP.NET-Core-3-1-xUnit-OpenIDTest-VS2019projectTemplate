Imports System
Imports System.Net.Http
Imports Xunit
Imports Newtonsoft.Json.Linq
Imports Newtonsoft.Json
Imports System.Text
Imports System.Threading.Tasks
Imports IdentityModel.Client
Imports Xunit.Abstractions
Imports Xunit.Sdk
Imports System.IdentityModel.Tokens.Jwt

Public Class TestNetCoreIdentity

    Private ReadOnly _Output As ITestOutputHelper

    Public Sub New(testOutput As ITestOutputHelper)
        _Output = testOutput
    End Sub

    Dim Client As HttpClient
    Dim ServerURL As String = "http://localhost:44347/api/customers"
    Dim ProtectedApiScope As String = "bankOfDotNetApi"
    Dim TokenResponse As IdentityModel.Client.TokenResponse
    Dim Disco As Task(Of DiscoveryDocumentResponse)
    Dim PostCustomerResponse As Task(Of HttpResponseMessage)
    Dim GetCustomerResponse As Task(Of HttpResponseMessage)
    Dim TestData = New StringContent(
                JsonConvert.SerializeObject(
                        New With {.Id = 10, .FirstName = "Viacheslav", .LastName = "Eremin"}),
                        Encoding.UTF8, "application/json")

    <Fact>
    Sub TestAuServer()

        'discover all the endpoints using metaData of identity server 
        'DiscoveryEndpoint for /.well-known/openid-configuration
        Client = New HttpClient()
        Disco = Client.GetDiscoveryDocumentAsync("http://localhost:5000")

        If Disco.Result.IsError Then
            Throw New XunitException(Disco.Result.[Error])
        End If

        Assert.Equal("http://localhost:5000/connect/token", Disco.Result?.TokenEndpoint)

        'Grab a bearer token 
        'by clear body Like 
        'grant_type=client_credentials&scope=bankOfDotNetApi&client_id=Login1&client_secret=Password1
        Dim ClearBody = New ClientCredentialsTokenRequest With
        {
            .Address = Disco.Result?.TokenEndpoint,
            .ClientId = "Login1",
            .ClientSecret = "Password1",
            .Scope = ProtectedApiScope
        }

        TokenResponse = Client.RequestClientCredentialsTokenAsync(ClearBody).Result

        Assert.True(TokenResponse.Raw.StartsWith("{""access_token"":"))
        _Output.WriteLine(TokenResponse.HttpStatusCode & " : " & TokenResponse.Raw)

        'Set hashCode in header as Basic AU  'Authorization: Basic TG9naW4xOlBhc3N3b3JkMQ=='
        Dim NoBody = New ClientCredentialsTokenRequest With
            {
                .Address = Disco.Result.TokenEndpoint,
                .AuthorizationHeaderStyle = BasicAuthenticationHeaderStyle.Rfc6749,
                .Scope = ProtectedApiScope
            }

        Client.SetBasicAuthenticationOAuth(ClearBody.ClientId, ClearBody.ClientSecret)
        Assert.True(Client.DefaultRequestHeaders.Authorization.ToString = "Basic TG9naW4xOlBhc3N3b3JkMQ==")

        TokenResponse = Client.RequestClientCredentialsTokenAsync(NoBody).Result

        If TokenResponse.IsError Then
            Throw New XunitException(TokenResponse.[Error])
        End If

        Assert.True(TokenResponse.Raw.StartsWith("{""access_token"":"))
        _Output.WriteLine(DecodeJwtToken)

    End Sub

    <Fact>
    Sub TestDataServerWithoutAU()
        Client = New HttpClient()
        PostCustomerResponse = Client.PostAsync(ServerURL, TestData)
        GetCustomerResponse = Client.GetAsync(ServerURL)

        Try
            Assert.True(GetCustomerResponse.Result IsNot Nothing)
        Catch ex As Exception
            Throw New XunitException("Server not wotking? , check " & ServerURL & vbCrLf & ex.Message)
        End Try

        Dim Res As String = GetCustomerResponse.Result.StatusCode & " : " & IIf(String.IsNullOrEmpty(GetCustomerResponse.Result.ReasonPhrase), "", GetCustomerResponse.Result.ReasonPhrase)
        _Output.WriteLine(Res)

        If Not GetCustomerResponse.Result?.IsSuccessStatusCode Then
            Assert.Equal("401 : Unauthorized", Res)
        Else
            Dim content = GetCustomerResponse.Result.Content.ReadAsStringAsync()
            _Output.WriteLine(JArray.Parse(content.Result).ToString)
        End If
    End Sub

    <Fact>
    Sub TestDataServerWithAU()

        TestAuServer()
        Client.SetBearerToken(TokenResponse.AccessToken)

        PostCustomerResponse = Client.PostAsync(ServerURL, TestData)
        GetCustomerResponse = Client.GetAsync(ServerURL)

        Try
            Assert.True(GetCustomerResponse.Result IsNot Nothing)
        Catch ex As Exception
            Throw New XunitException("Server not wotking? , check " & ServerURL & vbCrLf & ex.Message)
        End Try

        Dim Res As String = GetCustomerResponse.Result.StatusCode & " : " & IIf(String.IsNullOrEmpty(GetCustomerResponse.Result.ReasonPhrase), "", GetCustomerResponse.Result.ReasonPhrase)
        _Output.WriteLine(Res)

        If GetCustomerResponse.Result?.IsSuccessStatusCode Then
            Assert.Equal("200 : OK", Res)
        Else
            Throw New XunitException(Res)
        End If

        Dim content = GetCustomerResponse.Result.Content.ReadAsStringAsync()
        _Output.WriteLine(JArray.Parse(content.Result).ToString)
    End Sub

    Function DecodeJwtToken() As String
        Dim Jwt As New JwtSecurityTokenHandler
        Dim AccessToken = Jwt.ReadJwtToken(TokenResponse.AccessToken)
        Dim RefreshToken As JwtSecurityToken
        If RefreshToken IsNot Nothing Then
            RefreshToken = Jwt.ReadJwtToken(TokenResponse.RefreshToken)
        End If
        Dim AccessTokenFormated = JsonConvert.SerializeObject(AccessToken.Payload, Formatting.Indented)
        Dim RefreshTokenFormated = JsonConvert.SerializeObject(RefreshToken?.Payload, Formatting.Indented)
        Return "Token expired:" & TokenResponse.ExpiresIn.ToString & vbCrLf & AccessTokenFormated & vbCrLf & RefreshTokenFormated
    End Function

End Class
