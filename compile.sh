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

info "Compilando..."
g++  *.cpp */*.cpp *.h */*.h -o main.out --optimize=fast -std=c++20 -lwolfssl|| handle_error "La compilación falló"
success "Compilación exitosa."