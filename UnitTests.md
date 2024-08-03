## Configuración de Google Test

Guía para instalar y configurar Google Test.

### Requisitos Previos

Privilegios de `sudo` y gestor de paquetes esté actualizado.

### Instalación y Configuración

1. **Instalar Google Test y CMake:**

   ```sh
   sudo apt install libgtest-dev googletest
   sudo apt install cmake
   ```

2. **Compilar Google Test:**

   ```sh
   cd /usr/src/gtest
   sudo cmake -Bbuild
   sudo cmake --build build
   sudo cp ./build/lib/libgtest* /usr/lib/
   ```

3. **Navegar al Directorio de tu Proyecto:**

   ```sh
   cd /ruta/a/tu/proyecto/Google_tests/NewTests
   ```

4. **Compilar tus Tests:**

   ```sh
   cmake -Bbuild
   cmake --build build
   ```

5. **Ejecutar tus Tests:**
   ```sh
   cd build
   ./Google_Tests_run
   ```

### Notas Adicionales

- Reemplazar `/ruta_proyecto` con la ruta real al directorio del proyecto.
