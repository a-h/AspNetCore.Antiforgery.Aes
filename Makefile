build:
	dotnet restore
	dotnet build

test:
	dotnet test ./tests/AspNetCore.Antiforgery.Aes.Tests/AspNetCore.Antiforgery.Aes.Tests.csproj

pack:
	dotnet pack --no-build ./src/AspNetCore.Antiforgery.Aes/
	dotnet nuget push -s https://www.nuget.org/api/v2/ ./src/AspNetCore.Antiforgery.Aes/bin/Debug/AspNetCore.Antiforgery.Aes.1.0.0.nupkg