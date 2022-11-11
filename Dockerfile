FROM mcr.microsoft.com/dotnet/sdk:6.0
WORKDIR /app
COPY . /app
RUN dotnet restore "Compass.API/Compass.API.csproj"
RUN dotnet restore "Compass.Data/Compass.Data.csproj"
RUN dotnet restore "Compass.Services/Compass.Services.csproj"

RUN dotnet publish -c Release -o /app/build

EXPOSE 80
EXPOSE 443
EXPOSE 8080

WORKDIR /app/build
CMD ["dotnet", "Compass.API.dll", "--urls", "http://0.0.0.0:8080"]
