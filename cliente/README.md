# Instalacion
$ choco install -y golang           // Instalamos GO
$ go version                        // Comprobamos que se instalo y que version tenemos
$ $env:GOPATH                       // Comprobamos que está configurada la variable de entorno, al usar Chocolatey debe de haberse configurado

$ go get github.com/zserge/lorca    // Cargamos lorca en nuestro pc para poder usar el entorno gráfico.

# Despliegue
go run .\main