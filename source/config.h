// config.h - Configuration variables
#ifndef CONFIG_H
#define CONFIG_H

// Directory paths - updated to match your structure
#define UPLOAD_DIR "/media/sf_CA1/manufacturing/upload"
#define REPORT_DIR "/media/sf_CA1/manufacturing/report"
#define BACKUP_DIR "/media/sf_CA1/manufacturing/backup"
#define LOGS_DIR "/media/sf_CA1/manufacturing/logs"

// File for tracking changes
#define CHANGES_LOG "/media/sf_CA1/manufacturing/logs/changes.log"
#define ERROR_LOG "/media/sf_CA1/manufacturing/logs/error.log"
#define INFO_LOG "/media/sf_CA1/manufacturing/logs/info.log"

// Department names for checking missing reports
#define DEPT_COUNT 4
const char *DEPARTMENTS[DEPT_COUNT] = {
    "Warehouse",
    "Manufacturing",
    "Sales",
    "Distribution"
};

// Time settings
#define TRANSFER_HOUR 1   // 1 AM
#define TRANSFER_MIN 0
#define DEADLINE_HOUR 23  // 11:30 PM
#define DEADLINE_MIN 30

#endif