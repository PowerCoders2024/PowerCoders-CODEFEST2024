# PowerCoders-CODEFEST2024

![PowerCodersLogo](./PowerCodersLogo.png)

## Desarrolladores:

- Danny Camilo Muñoz Sanabria
- Diego Alejandro Pulido Bonilla
- Juan Camilo Lopez Cortes
- Johan Alexis Bautista Quinayas

## Descripción

Este proyecto se desarrolla bajo la participación del equipo POWERCODERS en el CODEFEST-2024. Se implementa un sistema de comunicación segura entre una estación terrestre y un activo espacial con limitaciones importantes de memoria dinámica utilizando cifrado avanzado y claves precompartidas (PSK).

## Requisitos del reto

- ✅ Pruebas y evaluación estática del código (Documento)
- ✅ Pruebas unitarias (En la rama UnitTests, adicionalmente hay un readme UnitTests.md para ejecutar las pruebas)
- ✅ Inline comments y documentación
- ✅ Documento de la solución
- ✅ Video

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

Script para compilar el proyecto. Ejecuta los comandos necesarios para construir los archivos objeto y enlazarlos en un ejecutable final. Es una alternativa al make que ya creamos.

### `main.cpp`

Archivo principal del proyecto que coordina la ejecución de las diferentes partes del sistema, incluyendo la inicialización de los componentes y la gestión de la comunicación entre el cliente terrestre y el servidor satelital.

# Instalación

Sigue estos pasos para instalar las dependencias y configurar el entorno de desarrollo:

1. Clona el repositorio:

   ```sh
   git clone https://github.com/PowerCoders2024/PowerCoders-CODEFEST2024.git
   cd PowerCoders-CODEFEST2024

   ```
2.   Ejecuta el script para compilar
    ```sh
      ./compile.sh
    ```
4.  Ejecutar el archivo principal:

    ```sh
    ./main <instruction> <input path> <output path>
    ```
