#!/bin/bash

# Definición de colores usando tput
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
RESET=$(tput sgr0)

# Función para manejar errores
handle_error() {
    echo "${RED}Error: $1${RESET}" >&2
    exit 1
}

# Función para mensajes informativos
info() {
    echo "${YELLOW}$1${RESET}"
}

# Función para mensajes de éxito
success() {
    echo "${GREEN}$1${RESET}"
}

# Cambiar al directorio de wolfSSL
cd ./libraries/wolfssl-5.7.2 || handle_error "No se pudo cambiar al directorio wolfssl-5.7.2"

info "Configurando wolfSSL..."
./configure --enable-all || handle_error "La configuración de wolfSSL falló"

info "Compilando wolfSSL..."
make || handle_error "La compilación de wolfSSL falló"

info "Instalando wolfSSL..."
sudo make install || handle_error "La instalación de wolfSSL falló"

success "wolfSSL se ha instalado correctamente!!!"