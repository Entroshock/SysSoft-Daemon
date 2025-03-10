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
#include <sys/wait.h> 
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
int execute_command(char *command, char *args[]); // Added

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
        process_ipc_messages();
        
        sleep(60); // Check every minute
    }
    
    log_info("Daemon shutting down");
    closelog();
    return 0;
}

// Execute command using fork and exec
int execute_command(char *command, char *args[]) {
    pid_t pid;
    int status;
    
    // Debug output
    char cmd_str[256] = "";
    for (int i = 0; args[i] != NULL; i++) {
        strcat(cmd_str, args[i]);
        strcat(cmd_str, " ");
    }
    log_info("Executing command: %s", cmd_str);
    
    // Temporarily change SIGCHLD handling
    signal(SIGCHLD, SIG_DFL);
    
    pid = fork();
    
    if (pid < 0) {
        // Fork failed
        log_error("Fork failed: %s", strerror(errno));
        signal(SIGCHLD, SIG_IGN); // Reset signal handling
        return -1;
    } 
    else if (pid == 0) {
        // Child process
        execvp(command, args);
        
        // If we get here, exec failed
        log_error("Exec failed for command %s: %s", command, strerror(errno));
        exit(EXIT_FAILURE);
    } 
    else {
        // Parent process
        if (waitpid(pid, &status, 0) == -1) {
            if (errno == ECHILD) {
                // Child already reaped
                log_info("Child process already reaped");
                signal(SIGCHLD, SIG_IGN); // Reset signal handling
                return 0; // Assume success
            } else {
                log_error("Wait failed: %s", strerror(errno));
                signal(SIGCHLD, SIG_IGN); // Reset signal handling
                return -1;
            }
        }
        
        // Reset signal handling
        signal(SIGCHLD, SIG_IGN);
        
        if (WIFEXITED(status)) {
            // Command executed successfully
            int exit_status = WEXITSTATUS(status);
            if (exit_status != 0) {
                log_error("Command %s exited with non-zero status: %d", command, exit_status);
                return exit_status;
            }
            log_info("Command executed successfully");
            return 0;
        } else if (WIFSIGNALED(status)) {
            log_error("Command %s terminated by signal: %d", command, WTERMSIG(status));
            return -1;
        }
    }
    
    return -1;
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
                char src_path[PATH_MAX];
                char dest_path[PATH_MAX];
                
                snprintf(src_path, sizeof(src_path), "%s/%s", UPLOAD_DIR, entry->d_name);
                snprintf(dest_path, sizeof(dest_path), "%s/%s", REPORT_DIR, entry->d_name);
                
                // Use exec to copy file
                char *cp_args[] = {"cp", src_path, dest_path, NULL};
                int status = execute_command("cp", cp_args);
                
                if (status == 0) {
                    // Success, now remove from upload dir
                    char *rm_args[] = {"rm", src_path, NULL};
                    status = execute_command("rm", rm_args);
                    
                    if (status != 0) {
                        log_error("Failed to remove source file after transfer");
                    } else {
                        file_count++;
                    }
                } else {
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
    time_t now;
    struct tm *timeinfo;
    char timestamp[20];
    char backup_path[1024];
    
    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", timeinfo);
    
    log_info("Starting backup operation");
    
    // Create backup directory with timestamp
    snprintf(backup_path, sizeof(backup_path), "%s/backup-%s", BACKUP_DIR, timestamp);
    
    // Create directory using exec
    char *mkdir_args[] = {"mkdir", "-p", backup_path, NULL};
    int status = execute_command("mkdir", mkdir_args);
    
    if (status != 0) {
        log_error("Failed to create backup directory");
        return;
    }
    
    // Create backup file path - ensure adequate buffer size
    char backup_file[PATH_MAX]; // Use PATH_MAX for maximum path length
    int ret = snprintf(backup_file, sizeof(backup_file), "%s/backup.tar.gz", backup_path);
    
    // Check for truncation or error
    if (ret < 0) {
        log_error("Error formatting backup path");
        return;
    } else if ((size_t)ret >= sizeof(backup_file)) {
        log_error("Backup path too long, truncation occurred");
        return;
    }
    
    // Use tar with exec to create backup
    char *tar_args[] = {"tar", "-czf", backup_file, "-C", REPORT_DIR, ".", NULL};
    status = execute_command("tar", tar_args);
    
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