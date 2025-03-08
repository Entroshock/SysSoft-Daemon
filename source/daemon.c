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
#include <errno.h>
#include <stdarg.h>
#include <limits.h>  // For PATH_MAX constant

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
void log_error(const char *format, ...); 
void log_info(const char *format, ...);   
void process_ipc_messages();              
void check_missing_reports();             


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
    
  
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    
   
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
    
    // Initialize the signal action struct
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    // Register signal handlers
    sigaction(SIGTERM, &sa, NULL);  // Termination signal
    sigaction(SIGINT, &sa, NULL);   // Interrupt signal 
    sigaction(SIGUSR1, &sa, NULL);  // User-defined signal 1 (manual backup/transfer)
    sigaction(SIGHUP, &sa, NULL);   // Hangup signal (reload configuration)
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
        default:
            log_info("Received unhandled signal: %d", sig);
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
                        snprintf(expected, sizeof(expected), "%s_%s.xml", DEPARTMENTS[i], today);
                        
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
                    snprintf(message, sizeof(message), "Missing report from %s department", DEPARTMENTS[i]);
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
            snprintf(path, sizeof(path), "%s/%s", UPLOAD_DIR, entry->d_name);
            
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
    char *cmd; // Make this dynamic to handle very long paths
    int status;
    int file_count = 0;
    
    log_info("Starting file transfer operation");
    
    dir = opendir(UPLOAD_DIR);
    
    if (dir == NULL) {
        log_error("Failed to open upload directory");
        return;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) { // Regular file
            if (strstr(entry->d_name, ".xml") != NULL) {
                char src_path[PATH_MAX];  // Use PATH_MAX for maximum path length
                char dest_path[PATH_MAX];
                
                snprintf(src_path, sizeof(src_path), "%s/%s", UPLOAD_DIR, entry->d_name);
                snprintf(dest_path, sizeof(dest_path), "%s/%s", REPORT_DIR, entry->d_name);
                
                // Calculate required buffer size and allocate appropriately
                size_t cmd_size = strlen("cp ") + strlen(src_path) + strlen(" ") + 
                                 strlen(dest_path) + 1; // +1 for null terminator
                cmd = malloc(cmd_size);
                
                if (cmd == NULL) {
                    log_error("Memory allocation failed for command buffer");
                    continue;
                }
                
                // Use the right size for the command buffer
                snprintf(cmd, cmd_size, "cp %s %s", src_path, dest_path);
                status = system(cmd);
                
                if (status == 0) {
                    // Success, now remove from upload dir
                    free(cmd); // Free the first command buffer
                    
                    // Allocate for the rm command
                    cmd_size = strlen("rm ") + strlen(src_path) + 1;
                    cmd = malloc(cmd_size);
                    
                    if (cmd == NULL) {
                        log_error("Memory allocation failed for command buffer");
                        continue;
                    }
                    
                    snprintf(cmd, cmd_size, "rm %s", src_path);
                    status = system(cmd);
                    free(cmd);
                    
                    if (status != 0) {
                        log_error("Failed to remove source file after transfer");
                    } else {
                        file_count++;
                    }
                } else {
                    free(cmd);
                    log_error("Failed to transfer file");
                }
            }
        }
    }
    
    closedir(dir);
    
    log_info("File transfer operation completed (%d files processed)", file_count);
    
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
    snprintf(backup_path, sizeof(backup_path), "%s/backup-%s", BACKUP_DIR, timestamp);
    mkdir(backup_path, 0755);
    
    // Use tar to create backup
    snprintf(cmd, sizeof(cmd), "tar -czf %s/backup.tar.gz -C %s .", backup_path, REPORT_DIR);
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
    
    // Get current permissions
    struct stat upload_stat, report_stat;
    if (stat(UPLOAD_DIR, &upload_stat) != 0 || stat(REPORT_DIR, &report_stat) != 0) {
        log_error("Failed to get directory permissions");
        return;
    }
    
    // Store original permissions for later restoration
    mode_t upload_mode = upload_stat.st_mode;
    mode_t report_mode = report_stat.st_mode;
    
    // Save original permissions to a file for restoration
    FILE *fp = fopen("/tmp/manufacturing_daemon_permissions", "w");
    if (fp != NULL) {
        fprintf(fp, "%o %o", upload_mode, report_mode);
        fclose(fp);
    }
    
    // Remove write permissions
    if (chmod(UPLOAD_DIR, 0555) != 0) {
        log_error("Failed to lock upload directory");
    }
    
    if (chmod(REPORT_DIR, 0555) != 0) {
        log_error("Failed to lock report directory");
    }
    
    log_info("Directories locked successfully");
}

// Unlock directories after backup/transfer
void unlock_directories() {
    log_info("Unlocking directories after backup/transfer");
    
    // Try to restore original permissions from saved file
    FILE *fp = fopen("/tmp/manufacturing_daemon_permissions", "r");
    if (fp != NULL) {
        mode_t upload_mode, report_mode;
        if (fscanf(fp, "%o %o", &upload_mode, &report_mode) == 2) {
            chmod(UPLOAD_DIR, upload_mode);
            chmod(REPORT_DIR, report_mode);
        } else {
            // Fallback to default permissions
            chmod(UPLOAD_DIR, 0755);
            chmod(REPORT_DIR, 0755);
        }
        fclose(fp);
    } else {
        // Fallback to default permissions
        chmod(UPLOAD_DIR, 0755);
        chmod(REPORT_DIR, 0755);
    }
    
    log_info("Directories unlocked successfully");
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
    
    if (key == -1) {
        log_error("Failed to create IPC key: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    // Create the message queue
    msgqid = msgget(key, 0666 | IPC_CREAT);
    
    if (msgqid == -1) {
        log_error("Failed to create message queue for IPC: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    log_info("IPC message queue created successfully");
}


void process_ipc_messages() {
    struct msg_buffer message;
    
    // Try to receive message without blocking
    if (msgrcv(msgqid, &message, sizeof(message.msg_text), 1, IPC_NOWAIT) != -1) {
        log_info("Received IPC message: %s", message.msg_text);
        
        if (strcmp(message.msg_text, "BACKUP_TRANSFER") == 0) {
            log_info("Manual backup/transfer requested via IPC");
            lock_directories();
            transfer_files();
            backup_files();
            unlock_directories();
            
            // Send response message
            struct msg_buffer response;
            response.msg_type = 2;
            strcpy(response.msg_text, "BACKUP_TRANSFER_COMPLETE");
            msgsnd(msgqid, &response, sizeof(response.msg_text), 0);
        }
        else if (strcmp(message.msg_text, "STATUS") == 0) {
            // Send status response
            struct msg_buffer response;
            response.msg_type = 2;
            strcpy(response.msg_text, "DAEMON_RUNNING");
            msgsnd(msgqid, &response, sizeof(response.msg_text), 0);
        }
    }
}

// Log error messages
void log_error(const char *format, ...) {
    FILE *fp;
    time_t now;
    struct tm *timeinfo;
    char timestamp[20];
    va_list args;
    
    // Get current timestamp
    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    // Open log file
    fp = fopen(ERROR_LOG, "a");
    
    if (fp != NULL) {
        // Write timestamp and prefix
        fprintf(fp, "[%s] ERROR: ", timestamp);
        
        // Handle variable arguments for the actual message
        va_start(args, format);
        vfprintf(fp, format, args);
        va_end(args);
        
        // Add newline and close file
        fprintf(fp, "\n");
        fclose(fp);
    }
    
    // Also log to syslog
    va_start(args, format);
    vsyslog(LOG_ERR, format, args);
    va_end(args);
}

// Log informational messages
void log_info(const char *format, ...) {
    FILE *fp;
    time_t now;
    struct tm *timeinfo;
    char timestamp[20];
    va_list args;
    
    // Get current timestamp
    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    // Open log file
    fp = fopen(INFO_LOG, "a");
    
    if (fp != NULL) {
        // Write timestamp and prefix
        fprintf(fp, "[%s] INFO: ", timestamp);
        
        // Handle variable arguments for the actual message
        va_start(args, format);
        vfprintf(fp, format, args);
        va_end(args);
        
        // Add newline and close file
        fprintf(fp, "\n");
        fclose(fp);
    }
    
    // Also log to syslog
    va_start(args, format);
    vsyslog(LOG_INFO, format, args);
    va_end(args);
}