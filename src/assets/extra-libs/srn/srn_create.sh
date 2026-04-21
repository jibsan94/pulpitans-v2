#!/bin/bash

set -euo pipefail

# Configuración
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Añadir pandoc al PATH si está disponible en la ubicación de despliegue
PANDOC_BIN="${SCRIPT_DIR}/pandoc/pandoc-3.9/bin"
if [ -d "$PANDOC_BIN" ]; then
    export PATH="${PANDOC_BIN}:$PATH"
fi

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

# Directorio temporal para configuración de DeNote (inicializado vacío)
DN_CONFIG_TMP=""

# Función para limpiar en caso de error
cleanup() {
    if [ -d "/tmp/idas_md" ]; then
        log_warning "Limpiando directorio temporal..."
        rm -rf /tmp/idas_md
    fi
    if [ -n "$DN_CONFIG_TMP" ] && [ -d "$DN_CONFIG_TMP" ]; then
        rm -rf "$DN_CONFIG_TMP"
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

# Directorio de build y rutas de proyecto (pueden ser sobreescritas por el servidor Flask)
SRN_BUILD_DIR="${SRN_BUILD_DIR:-${SCRIPT_DIR}/build}"
PROJECTS_PATH="${PROJECTS_PATH:-/iDASREPO/PROJECTS}"
IDASPKG_RELPATH="${IDASPKG_RELPATH:-/repos/pxeBase/iDASpkg}"

# Detecta el directorio del proyecto a partir del nombre de la rama
detect_project_folder() {
    local branch="$1"
    if [ -d "${PROJECTS_PATH}" ]; then
        for folder in "${PROJECTS_PATH}"/*/; do
            [ -d "$folder" ] || continue
            local fname
            fname=$(basename "$folder")
            if [[ "$branch" == "$fname" || "$branch" == "${fname}_"* ]]; then
                echo "$fname"
                return 0
            fi
        done
    fi
    # Fallback: parte antes del primer _
    echo "${branch%%_*}"
}

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

# Paso 1: Usar repo existente o clonar si no existe
REPO_DIR="${REPO_DIR:-}"
if [ -n "$REPO_DIR" ] && [ -d "$REPO_DIR" ]; then
    log_info "Usando repositorio existente en: $REPO_DIR"
    WORK_DIR="$REPO_DIR"
else
    log_info "Clonando repositorio..."
    if [ -d "/tmp/idas_md" ]; then
        log_warning "El directorio /tmp/idas_md ya existe. Eliminándolo..."
        rm -rf /tmp/idas_md
    fi
    git clone https://bitbucket.indra.es/scm/gt_idas/idas_md.git /tmp/idas_md || {
        log_error "Fallo al clonar el repositorio"
        exit 1
    }
    WORK_DIR="/tmp/idas_md"
fi

# Paso 2: Checkout y pull
log_info "Cambiando a branch '$PROJECT' y actualizando..."
cd "$WORK_DIR"
git checkout "$PROJECT" || {
    log_error "Fallo al hacer checkout a la rama '$PROJECT'"
    exit 1
}

git pull || {
    log_error "Fallo al hacer pull"
    exit 1
}

# Paso 3: Ejecutar DeNote.sh
# Derivar -w (directorio padre) y -r (nombre del repo) desde WORK_DIR
REPO_WORK_DIR=$(dirname "$WORK_DIR")
REPO_NAME=$(basename "$WORK_DIR")

# Crear directorio temporal escribible para DN_CONFIG
# (/TOOLS/iDAS_DeNote/ pertenece a otro usuario y no tiene permisos de escritura)
DN_CONFIG_TMP=$(mktemp -d)
cp /TOOLS/iDAS_DeNote/dn_content.*.bash "$DN_CONFIG_TMP/" 2>/dev/null || true
cp /TOOLS/iDAS_DeNote/*.html "$DN_CONFIG_TMP/" 2>/dev/null || true
log_info "Configuración DN_CONFIG copiada a: $DN_CONFIG_TMP"

log_info "Ejecutando DeNote.sh (repo: $REPO_NAME, workdir: $REPO_WORK_DIR)..."
/TOOLS/Analysis/DeNote.sh \
    -P MD \
    -g \
    -d \
    -l "$LABEL" \
    -r "$REPO_NAME" \
    -w "$REPO_WORK_DIR" \
    -c "$DN_CONFIG_TMP/" \
    -b "$PROJECT" || {
    log_warning "DeNote.sh terminó con error (código: $?). Continuando con la generación del SRN..."
}

# Paso 4: Crear estructura de directorios
log_info "Creando estructura de directorios para SRNs..."
DEST_DIR="${SRN_BUILD_DIR}/${LABEL}"
mkdir -p "$DEST_DIR" || {
    log_error "Fallo al crear directorio $DEST_DIR"
    exit 1
}

# Paso 4.1: Escribir metadatos de la SRN
cat > "${DEST_DIR}/.srn_meta" << METAEOF
project=${PROJECT}
label=${LABEL}
generated=$(date '+%Y-%m-%d %H:%M:%S')
METAEOF

# Paso 4.2: Generar packages.txt
log_info "Generando packages.txt..."
PROJECT_FOLDER=$(detect_project_folder "$PROJECT")
PKG_DIR="${PROJECTS_PATH}/${PROJECT_FOLDER}${IDASPKG_RELPATH}"
if [ -d "$PKG_DIR" ]; then
    find "$PKG_DIR" -maxdepth 1 -type f -exec md5sum {} \; \
        | sed "s|${PKG_DIR}/||" > "${DEST_DIR}/packages.txt" \
        && log_info "  ✓ packages.txt generado (proyecto: $PROJECT_FOLDER)"
else
    log_warning "  ✗ Directorio de paquetes no encontrado: $PKG_DIR"
    echo "# No se encontró el directorio: $PKG_DIR" > "${DEST_DIR}/packages.txt"
fi

# Paso 5: Mover archivos generados
log_info "Moviendo archivos generados a $DEST_DIR..."

# Array de archivos a mover
# - arco.py escribe Query.txt y change_revision_errors.log en /tmp/
# - DeNote.sh escribe el resto en REPO_WORK_DIR
FILES_TO_MOVE=(
    "/tmp/${LABEL}.Query.txt"
    "${REPO_WORK_DIR}/All_Git_Commits_in_build.txt"
    "${REPO_WORK_DIR}/All_Git_Error_Commits_in_build.txt"
    "${REPO_WORK_DIR}/All_Git_PTRs_in_build.txt"
    "/tmp/change_revision_errors.log"
    "${REPO_WORK_DIR}/Change_Revision.html"
    "${REPO_WORK_DIR}/Change_Revision.log"
)

# Mover archivos desde /tmp
for file in "${FILES_TO_MOVE[@]}"; do
    if [ -f "$file" ]; then
        mv "$file" "$DEST_DIR/" && log_info "  ✓ Movido: $(basename "$file")"
    else
        log_warning "  ✗ No encontrado: $file"
    fi
done

# Mover y renombrar SRN.html (generado en el directorio temporal DN_CONFIG_TMP)
SRN_SOURCE="${DN_CONFIG_TMP}/SRN.html"
PROJECT_UPPER=$(echo "$PROJECT" | tr '[:lower:]' '[:upper:]')
SRN_NEW_NAME="[iDAS][${PROJECT_UPPER}] SRN iDAS_el8-${LABEL}.html"
SRN_DEST="${DEST_DIR}/${SRN_NEW_NAME}"

if [ -f "$SRN_SOURCE" ]; then
    cp "$SRN_SOURCE" "$SRN_DEST" && log_info "  ✓ Copiado y renombrado: $SRN_NEW_NAME"
else
    log_warning "No se encontró SRN.html en $SRN_SOURCE (DeNote.sh puede haber fallado)"
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