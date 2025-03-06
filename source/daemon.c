// daemon.c - Main daemon process
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <pwd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include "config.h"

// Global variables
int running = 1;
int msgqid;

// Message structure for IPC
struct msg_buffer {
    long msg_type;
    char msg_text[100];
};

// Function prototypes
void daemonize();
void signal_handler(int sig);
void setup_signals();
void check_files();
void transfer_files();
void backup_files();
void lock_directories();
void unlock_directories();
void log_changes(const char *username, const char *filename);
int check_time_for_operations();
void setup_ipc();
void log_error(const char *message);
void log_info(const char *message);

int main() {
    daemonize();
    setup_signals();
    setup_ipc();
    
    log_info("Daemon started successfully");
    
    // Main daemon loop
    while(running) {
        // Check if it's time for scheduled operations
        if (check_time_for_operations()) {
            lock_directories();
            transfer_files();
            backup_files();
            unlock_directories();
        }
        
        // Check for new/modified files and log changes
        check_files();
        
        // Check for IPC messages to trigger manual operations
        struct msg_buffer message;
        if (msgrcv(msgqid, &message, sizeof(message.msg_text), 1, IPC_NOWAIT) != -1) {
            if (strcmp(message.msg_text, "BACKUP_TRANSFER") == 0) {
                log_info("Manual backup/transfer requested");
                lock_directories();
                transfer_files();
                backup_files();
                unlock_directories();
            }
        }
        
        sleep(60); // Check every minute
    }
    
    log_info("Daemon shutting down");
    closelog();
    return 0;
}

// Turn the process into a daemon
void daemonize() {
    pid_t pid;
    
    // Fork off the parent process
    pid = fork();
    
    // An error occurred
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    
    // Success: Let the parent terminate
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    
    // On success: The child process becomes session leader
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }
    
    // Catch, ignore and handle signals
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    // Fork off for the second time
    pid = fork();
    
    // An error occurred
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    
    // Success: Let the parent terminate
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    
    // Set new file permissions
    umask(0);
    
    // Change the working directory to root to avoid issues with mounting
    chdir("/");
    
    // Close all open file descriptors
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }
    
    // Open logs
    openlog("manufacturing_daemon", LOG_PID, LOG_DAEMON);
    
    // Create required directories if they don't exist
    mkdir(UPLOAD_DIR, 0755);
    mkdir(REPORT_DIR, 0755);
    mkdir(BACKUP_DIR, 0755);
    mkdir(LOGS_DIR, 0755);
}

// Setup signal handlers
void setup_signals() {
    struct sigaction sa;
    
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL); // Can be used to trigger manual backup/transfer
}

// Signal handler function
void signal_handler(int sig) {
    switch(sig) {
        case SIGTERM:
            log_info("Received SIGTERM, shutting down...");
            running = 0;
            break;
        case SIGUSR1:
            log_info("Received SIGUSR1, triggering backup/transfer...");
            lock_directories();
            transfer_files();
            backup_files();
            unlock_directories();
            break;
    }
}

// Check if it's time for scheduled operations
int check_time_for_operations() {
    time_t now;
    struct tm *timeinfo;
    
    time(&now);
    timeinfo = localtime(&now);
    
    if (timeinfo->tm_hour == TRANSFER_HOUR && timeinfo->tm_min == TRANSFER_MIN) {
        return 1;
    }
    
    return 0;
}

// Check for missing reports at deadline
void check_missing_reports() {
    time_t now;
    struct tm *timeinfo;
    
    time(&now);
    timeinfo = localtime(&now);
    
    // Check at deadline (23:30)
    if (timeinfo->tm_hour == DEADLINE_HOUR && timeinfo->tm_min == DEADLINE_MIN) {
        DIR *dir;
        struct dirent *entry;
        char found[DEPT_COUNT] = {0};
        
        dir = opendir(UPLOAD_DIR);
        
        if (dir != NULL) {
            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_type == DT_REG) { // Regular file
                    char today[11];
                    time_t t = time(NULL);
                    struct tm *tm = localtime(&t);
                    strftime(today, sizeof(today), "%Y-%m-%d", tm);
                    
                    for (int i = 0; i < DEPT_COUNT; i++) {
                        char expected[256];
                        snprintf(expected, "%s_%s.xml", DEPARTMENTS[i], today);
                        
                        if (strcmp(entry->d_name, expected) == 0) {
                            found[i] = 1;
                            break;
                        }
                    }
                }
            }
            closedir(dir);
            
            // Log missing reports
            for (int i = 0; i < DEPT_COUNT; i++) {
                if (!found[i]) {
                    char message[256];
                    snprintf(message, "Missing report from %s department", DEPARTMENTS[i]);
                    log_error(message);
                }
            }
        }
    }
}

// Check for new/modified files and log changes
void check_files() {
    static time_t last_check = 0;
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;
    
    dir = opendir(UPLOAD_DIR);
    
    if (dir == NULL) {
        log_error("Failed to open upload directory");
        return;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) { // Regular file
            char path[512];
            snprintf(path, "%s/%s", UPLOAD_DIR, entry->d_name);
            
            if (stat(path, &file_stat) == 0) {
                if (file_stat.st_mtime > last_check && last_check > 0) {
                    // File was modified since last check
                    struct passwd *pw = getpwuid(file_stat.st_uid);
                    if (pw != NULL) {
                        log_changes(pw->pw_name, entry->d_name);
                    } else {
                        log_changes("unknown", entry->d_name);
                    }
                }
            }
        }
    }
    
    closedir(dir);
    
    // Update last check time
    time(&last_check);
    
    // Check for missing reports at deadline
    check_missing_reports();
}

// Transfer files from upload to report directory
void transfer_files() {
    DIR *dir;
    struct dirent *entry;
    char cmd[2048];
    int status;
    
    log_info("Starting file transfer operation");
    
    dir = opendir(UPLOAD_DIR);
    
    if (dir == NULL) {
        log_error("Failed to open upload directory");
        return;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) { // Regular file
            if (strstr(entry->d_name, ".xml") != NULL) {
                char src_path[1024];
                char dest_path[1024];
                
                snprintf(src_path, "%s/%s", UPLOAD_DIR, entry->d_name);
                snprintf(dest_path, "%s/%s", REPORT_DIR, entry->d_name);
                
                // Use system command to copy file
                snprintf(cmd, "cp %s %s", src_path, dest_path);
                status = system(cmd);
                
                if (status == 0) {
                    // Success, now remove from upload dir
                    snprintf(cmd, "rm %s", src_path);
                    status = system(cmd);
                    
                    if (status != 0) {
                        log_error("Failed to remove source file after transfer");
                    }
                } else {
                    log_error("Failed to transfer file");
                }
            }
        }
    }
    
    closedir(dir);
    
    log_info("File transfer operation completed");
    
    // Send IPC message indicating completion
    struct msg_buffer message;
    message.msg_type = 2;
    strcpy(message.msg_text, "TRANSFER_COMPLETE");
    msgsnd(msgqid, &message, sizeof(message.msg_text), 0);
}

// Backup reporting directory
void backup_files() {
    char cmd[2048];
    int status;
    time_t now;
    struct tm *timeinfo;
    char timestamp[20];
    
    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", timeinfo);
    
    log_info("Starting backup operation");
    
    // Create backup directory with timestamp
    char backup_path[1024];
    snprintf(backup_path, "%s/backup-%s", BACKUP_DIR, timestamp);
    mkdir(backup_path, 0755);
    
    // Use tar to create backup
    snprintf(cmd, "tar -czf %s/backup.tar.gz -C %s .", backup_path, REPORT_DIR);
    status = system(cmd);
    
    if (status != 0) {
        log_error("Backup operation failed");
    } else {
        log_info("Backup operation completed successfully");
    }
    
    // Send IPC message indicating completion
    struct msg_buffer message;
    message.msg_type = 2;
    strcpy(message.msg_text, "BACKUP_COMPLETE");
    msgsnd(msgqid, &message, sizeof(message.msg_text), 0);
}

// Lock directories during backup/transfer
void lock_directories() {
    log_info("Locking directories for backup/transfer");
    
    // Remove write permissions from directories
    chmod(UPLOAD_DIR, 0555);
    chmod(REPORT_DIR, 0555);
}

// Unlock directories after backup/transfer
void unlock_directories() {
    log_info("Unlocking directories after backup/transfer");
    
    // Restore write permissions
    chmod(UPLOAD_DIR, 0755);
    chmod(REPORT_DIR, 0755);
}

// Log file changes
void log_changes(const char *username, const char *filename) {
    FILE *fp;
    time_t now;
    struct tm *timeinfo;
    char timestamp[20];
    
    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    fp = fopen(CHANGES_LOG, "a");
    
    if (fp != NULL) {
        fprintf(fp, "[%s] User: %s, File: %s\n", timestamp, username, filename);
        fclose(fp);
    } else {
        log_error("Failed to open changes log file");
    }
}

// Setup IPC
void setup_ipc() {
    key_t key = ftok("/media/sf_CA1/manufacturing", 'A');
    
    // Create the message queue
    msgqid = msgget(key, 0666 | IPC_CREAT);
    
    if (msgqid == -1) {
        log_error("Failed to create message queue for IPC");
    }
}

// Log error messages
void log_error(const char *message) {
    FILE *fp;
    time_t now;
    struct tm *timeinfo;
    char timestamp[20];
    
    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    fp = fopen(ERROR_LOG, "a");
    
    if (fp != NULL) {
        fprintf(fp, "[%s] ERROR: %s\n", timestamp, message);
        fclose(fp);
    }
    
    syslog(LOG_ERR, "ERROR: %s", message);
}

// Log informational messages
void log_info(const char *message) {
    FILE *fp;
    time_t now;
    struct tm *timeinfo;
    char timestamp[20];
    
    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    fp = fopen(INFO_LOG, "a");
    
    if (fp != NULL) {
        fprintf(fp, "[%s] INFO: %s\n", timestamp, message);
        fclose(fp);
    }
    
    syslog(LOG_INFO, "INFO: %s", message);
}