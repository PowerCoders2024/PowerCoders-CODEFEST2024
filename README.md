# PowerCoders-CODEFEST2024
## Desarrolladores:
- Danny Camilo Muñoz Sanabria
- Diego Alejandro Pulido Bonilla
- Juan Camilo Lopez Cortes
- Johan Alexis Bautista Quinayas

## Descripción
Este proyecto se desarrolla bajo la participación del equipo POWERCODERS en el CODEFEST-2024. Se implementa un sistema de comunicación segura entre una estación terrestre y un activo espacial con limitaciones importantes de memoria dinámica utilizando cifrado avanzado y claves precompartidas (PSK). 

## Estructura del Proyecto
El repositorio está organizado de la siguiente manera:

- **CryptoUser/**
  - `CryptoUser.cpp`: Implementación de las operaciones de usuario criptográfico.
  - `CryptoUser.h`: Definición de las operaciones de usuario criptográfico.
- **EarthClient/**
  - `EarthClient.cpp`: Código específico para el cliente terrestre que maneja la comunicación y autenticación.
- **SpaceServer/**
  - `SpaceServer.cpp`: Código específico para el servidor satelital que maneja la comunicación y autenticación.
- `CipherSuite.cpp`: Implementación de la suite de cifrado.
- `CipherSuite.h`: Definición de la suite de cifrado.
- `README.md`: Este archivo que estás leyendo.
- `compile.sh`: Script para compilar el proyecto.
- `main.cpp`: Archivo principal del proyecto.
- `makefile`: Archivo para la construcción del proyecto.
- `pre-compile.sh`: Script de pre-compilación.

## Descripción de los Componentes
### CryptoUser
`CryptoUser.cpp` y `CryptoUser.h`
Esta clase maneja las operaciones criptográficas del usuario, incluyendo la generación de claves, la configuración de la sesión de claves, y la encriptación y desencriptación de mensajes utilizando AES.
### EarthClient
`EarthClient.cpp`
Este archivo contiene el código para la estación terrestre. Se encarga de iniciar la suite de cifrado, recibir pistas de identidad del servidor, y enviar la identidad del cliente al satélite.
### SpaceServer
`SpaceServer.cpp`
Este archivo contiene el código para el servidor satelital. Se encarga de iniciar el contexto SSL, configurar las pistas de identidad PSK, y verificar la identidad del cliente.
### CipherSuite
`CipherSuite.cpp` y `CipherSuite.h`
La suite de cifrado proporciona métodos para inicializar el cifrado AES-GCM, generar claves PSK, y manejar la encriptación y desencriptación en bloques utilizando múltiples hilos para optimizar el rendimiento.
## Scripts y Archivos de Construcción
### `compile.sh`
Script para compilar el proyecto. Ejecuta los comandos necesarios para construir los archivos objeto y enlazarlos en un ejecutable final.
### `main.cpp`
Archivo principal del proyecto que coordina la ejecución de las diferentes partes del sistema, incluyendo la inicialización de los componentes y la gestión de la comunicación entre el cliente terrestre y el servidor satelital.
### `makefile`
Archivo utilizado por `make` para construir el proyecto. Define las reglas de compilación y las dependencias entre los archivos fuente y los archivos objeto.
### `pre-compile.sh`
Script de pre-compilación que realiza las tareas previas necesarias antes de la compilación del proyecto (configuración del entorno).

# Instalación
Sigue estos pasos para instalar las dependencias y configurar el entorno de desarrollo:

1. Clona el repositorio:
   ```sh
   git clone https://github.com/PowerCoders2024/PowerCoders-CODEFEST2024.git
   cd PowerCoders-CODEFEST2024
   
2. Compila el proyecto usando el script de compilación:
   ```sh
   ./pre-compile.sh
   ./compile.sh
> [!WARNING]
> Es importante que wolfssl-5.7.2 se encuentre en la carpeta `/libraries` para que se pueda compilar correctamente.

## Instalación manual 
En caso de fallo de los Scripts de construcción y compilación `pre-compile.sh` y `compile.sh` se puede hacer la configuración de entorno manualmente de la siguiente forma:

1. Configurar, compilar e instalar wolfSSL:
    ```sh
    cd ./libraries/wolfssl-5.7.2
    ./configure --enable-all
    make
    sudo make install
    cd ../..
2.Compilar el proyecto:
    
    g++  *.cpp */*.cpp *.h */*.h -o main.out --optimize=fast -std=c++20 -lwolfssl

3. Ejecutar el archivo principal:

    ```sh
    ./main <instruction> <input path> <output path>

