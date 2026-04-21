#!/bin/bash

set -euo pipefail

# Configuración
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.cfg"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Función para logging
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Función para limpiar en caso de error
cleanup() {
    if [ -d "/tmp/idas_md" ]; then
        log_warning "Limpiando directorio temporal..."
        rm -rf /tmp/idas_md
    fi
}

trap cleanup EXIT ERR

# Verificar existencia del archivo de configuración
if [ ! -f "$CONFIG_FILE" ]; then
    log_error "No se encontró el archivo de configuración: $CONFIG_FILE"
    exit 1
fi

# Cargar configuración
source "$CONFIG_FILE"

# Paso 0: Verificar y corregir permisos de /TOOLS
log_info "Verificando permisos de /TOOLS..."
CURRENT_USER=$(whoami)
TOOLS_OWNER=$(stat -c '%U' /TOOLS 2>/dev/null || stat -f '%Su' /TOOLS 2>/dev/null)

if [ -z "$TOOLS_OWNER" ]; then
    log_error "No se pudo verificar el propietario de /TOOLS. ¿Existe el directorio?"
    exit 1
fi

if [ "$TOOLS_OWNER" != "$CURRENT_USER" ]; then
    log_warning "El directorio /TOOLS pertenece a '$TOOLS_OWNER', no a '$CURRENT_USER'"
    log_info "Cambiando propietario de /TOOLS a '$CURRENT_USER' (requiere sudo)..."
    
    sudo chown -R "$CURRENT_USER":"$CURRENT_USER" /TOOLS || {
        log_error "Fallo al cambiar el propietario de /TOOLS. Verifica tus permisos de sudo."
        exit 1
    }
    
    log_info "  ✓ Propietario de /TOOLS cambiado correctamente"
else
    log_info "  ✓ /TOOLS ya pertenece a '$CURRENT_USER'"
fi

# Validar variables requeridas
if [ -z "${PROJECT:-}" ]; then
    log_error "La variable PROJECT no está definida en $CONFIG_FILE"
    exit 1
fi

if [ -z "${LABEL:-}" ]; then
    log_error "La variable LABEL no está definida en $CONFIG_FILE"
    exit 1
fi

log_info "Configuración cargada:"
log_info "  - PROJECT: $PROJECT"
log_info "  - LABEL: $LABEL"

# Paso 1: Git clone
log_info "Clonando repositorio..."
if [ -d "/tmp/idas_md" ]; then
    log_warning "El directorio /tmp/idas_md ya existe. Eliminándolo..."
    rm -rf /tmp/idas_md
fi

git clone https://bitbucket.indra.es/scm/gt_idas/idas_md.git /tmp/idas_md || {
    log_error "Fallo al clonar el repositorio"
    exit 1
}

# Paso 2: Checkout y pull
log_info "Cambiando a branch '$PROJECT' y actualizando..."
cd /tmp/idas_md
git checkout "$PROJECT" || {
    log_error "Fallo al hacer checkout a la rama '$PROJECT'"
    exit 1
}

git pull || {
    log_error "Fallo al hacer pull"
    exit 1
}

# Paso 3: Ejecutar DeNote.sh
log_info "Ejecutando DeNote.sh..."
/TOOLS/Analysis/DeNote.sh \
    -P MD \
    -g \
    -d \
    -l "$LABEL" \
    -r idas_md \
    -w /tmp \
    -c /TOOLS/iDAS_DeNote/ \
    -b "$PROJECT" || {
    log_error "Fallo al ejecutar DeNote.sh"
    exit 1
}

# Paso 4: Crear estructura de directorios
log_info "Creando estructura de directorios para SRNs..."
DEST_DIR="${HOME}/SRNs/${PROJECT}/${LABEL}"
mkdir -p "$DEST_DIR" || {
    log_error "Fallo al crear directorio $DEST_DIR"
    exit 1
}

# Paso 5: Mover archivos generados
log_info "Moviendo archivos generados a $DEST_DIR..."

# Array de archivos a mover desde /tmp
FILES_TO_MOVE=(
    "/tmp/${LABEL}.Query.txt"
    "/tmp/All_Git_Commits_in_build.txt"
    "/tmp/All_Git_Error_Commits_in_build.txt"
    "/tmp/All_Git_PTRs_in_build.txt"
    "/tmp/change_revision_errors.log"
    "/tmp/Change_Revision.html"
    "/tmp/Change_Revision.log"
)

# Mover archivos desde /tmp
for file in "${FILES_TO_MOVE[@]}"; do
    if [ -f "$file" ]; then
        mv "$file" "$DEST_DIR/" && log_info "  ✓ Movido: $(basename "$file")"
    else
        log_warning "  ✗ No encontrado: $file"
    fi
done

# Mover y renombrar SRN.html
SRN_SOURCE="/TOOLS/iDAS_DeNote/SRN.html"
PROJECT_UPPER=$(echo "$PROJECT" | tr '[:lower:]' '[:upper:]')
SRN_NEW_NAME="[iDAS][${PROJECT_UPPER}] SRN iDAS_el8-${LABEL}.html"
SRN_DEST="${DEST_DIR}/${SRN_NEW_NAME}"

if [ -f "$SRN_SOURCE" ]; then
    mv "$SRN_SOURCE" "$SRN_DEST" && log_info "  ✓ Movido y renombrado: $SRN_NEW_NAME"
else
    log_error "No se encontró el archivo SRN.html en $SRN_SOURCE"
    exit 1
fi

# Paso 6: Convertir HTML a DOCX y PDF
log_info "Intentando convertir SRN.html a DOCX y PDF..."

# Verificar si pandoc está instalado
if command -v pandoc &> /dev/null; then
    log_info "Convirtiendo HTML a DOCX..."
    DOCX_FILE="${DEST_DIR}/${SRN_NEW_NAME%.html}.docx"
    pandoc "$SRN_DEST" -o "$DOCX_FILE" && log_info "  ✓ DOCX generado: ${SRN_NEW_NAME%.html}.docx"
    
    # Intentar convertir a PDF (requiere wkhtmltopdf o similar)
    if command -v wkhtmltopdf &> /dev/null; then
        log_info "Convirtiendo HTML a PDF..."
        PDF_FILE="${DEST_DIR}/${SRN_NEW_NAME%.html}.pdf"
        wkhtmltopdf "$SRN_DEST" "$PDF_FILE" && log_info "  ✓ PDF generado: ${SRN_NEW_NAME%.html}.pdf"
    else
        log_warning "wkhtmltopdf no está instalado. No se generará el PDF."
        log_warning "Instala con: sudo yum install wkhtmltopdf (RHEL/CentOS) o sudo apt install wkhtmltopdf (Debian/Ubuntu)"
    fi
else
    log_warning "pandoc no está instalado. No se generarán DOCX ni PDF."
    log_warning "Instala con: sudo yum install pandoc (RHEL/CentOS) o sudo apt install pandoc (Debian/Ubuntu)"
fi

log_info "Proceso completado exitosamente"
log_info "Archivos ubicados en: $DEST_DIR"