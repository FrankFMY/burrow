#!/bin/bash
# Burrow Database Backup Script
#
# Usage: ./backup.sh [backup_dir]
#
# Environment variables:
#   BURROW_DB_PATH - Path to SQLite database (default: /data/burrow.db)
#   BACKUP_RETENTION_DAYS - Number of days to keep backups (default: 7)
#   S3_BUCKET - S3 bucket for remote backup (optional)
#   AWS_PROFILE - AWS profile to use (optional)

set -euo pipefail

# Configuration
DB_PATH="${BURROW_DB_PATH:-/data/burrow.db}"
BACKUP_DIR="${1:-/data/backups}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="burrow_backup_${TIMESTAMP}.db"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if database exists
if [ ! -f "$DB_PATH" ]; then
    log_error "Database not found at $DB_PATH"
    exit 1
fi

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

log_info "Starting backup of $DB_PATH"

# Create backup using SQLite's backup command (safe for live databases)
if command -v sqlite3 &> /dev/null; then
    sqlite3 "$DB_PATH" ".backup '$BACKUP_DIR/$BACKUP_NAME'"
else
    # Fallback to cp if sqlite3 is not available
    log_warn "sqlite3 not found, using file copy (ensure database is not being written to)"
    cp "$DB_PATH" "$BACKUP_DIR/$BACKUP_NAME"
fi

# Compress the backup
log_info "Compressing backup..."
gzip "$BACKUP_DIR/$BACKUP_NAME"
BACKUP_FILE="$BACKUP_DIR/${BACKUP_NAME}.gz"

# Get backup size
BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
log_info "Backup created: $BACKUP_FILE ($BACKUP_SIZE)"

# Upload to S3 if configured
if [ -n "${S3_BUCKET:-}" ]; then
    log_info "Uploading to S3 bucket: $S3_BUCKET"

    AWS_ARGS=""
    if [ -n "${AWS_PROFILE:-}" ]; then
        AWS_ARGS="--profile $AWS_PROFILE"
    fi

    if aws s3 cp "$BACKUP_FILE" "s3://$S3_BUCKET/backups/${BACKUP_NAME}.gz" $AWS_ARGS; then
        log_info "Backup uploaded to S3 successfully"
    else
        log_error "Failed to upload backup to S3"
    fi
fi

# Cleanup old backups
log_info "Cleaning up backups older than $RETENTION_DAYS days..."
find "$BACKUP_DIR" -name "burrow_backup_*.db.gz" -type f -mtime "+$RETENTION_DAYS" -delete

# Count remaining backups
BACKUP_COUNT=$(find "$BACKUP_DIR" -name "burrow_backup_*.db.gz" -type f | wc -l)
log_info "Backup complete. Total backups: $BACKUP_COUNT"

# Output summary
echo ""
echo "===== Backup Summary ====="
echo "Database: $DB_PATH"
echo "Backup: $BACKUP_FILE"
echo "Size: $BACKUP_SIZE"
echo "Retention: $RETENTION_DAYS days"
echo "=========================="
