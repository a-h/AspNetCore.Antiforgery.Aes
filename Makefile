build:
	dotnet restore
	dotnet build

pack:
	dotnet pack --no-build ./src/AspNetCore.Antiforgery.Aes/AspNetCore.Antiforgery.Aes.csproj
	dotnet nuget push -s https://www.nuget.org/api/v2/ ./src/AspNetCore.Antiforgery.Aes/bin/Debug/AspNetCore.Antiforgery.Aes.1.0.0.nupkg