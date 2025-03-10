// client.c - Enhanced client program with signal support
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <signal.h>
#include <unistd.h>
#include "config.h"

// Message structure for IPC
struct msg_buffer {
    long msg_type;
    char msg_text[100];
};

// Function to get daemon PID
// Updated get_daemon_pid function for client.c
pid_t get_daemon_pid() {
    FILE *fp = popen("pgrep -f 'manufacturing_daemon$'", "r");
    char buf[32];
    pid_t pid = -1;
    
    if (fp == NULL) {
        printf("Error: Could not check daemon status\n");
        return -1;
    }
    
    if (fgets(buf, sizeof(buf), fp) != NULL) {
        pid = atoi(buf);
    }
    
    pclose(fp);
    return pid;
}

int main(int argc, char *argv[]) {
    // Check for correct usage
    if (argc < 2) {
        printf("Usage: %s [backup|status|signal <type>]\n", argv[0]);
        printf("  backup - Trigger backup and transfer operations\n");
        printf("  status - Check if daemon is running\n");
        printf("  signal - Send a signal to the daemon\n");
        printf("    signal backup - Signal daemon to perform backup/transfer\n");
        printf("    signal reload - Signal daemon to reload configuration\n");
        return 1;
    }
    
    if (strcmp(argv[1], "backup") == 0) {
        // Send message to daemon to trigger backup/transfer
        key_t key = ftok("/media/sf_CA1/manufacturing", 'A');
        int msgqid = msgget(key, 0666);
        
        if (msgqid == -1) {
            printf("Error: Could not access message queue. Is the daemon running?\n");
            return 1;
        }
        
        struct msg_buffer message;
        message.msg_type = 1;
        strcpy(message.msg_text, "BACKUP_TRANSFER");
        
        if (msgsnd(msgqid, &message, sizeof(message.msg_text), 0) == -1) {
            printf("Error: Could not send message to daemon\n");
            return 1;
        }
        
        printf("Backup/transfer request sent to daemon\n");
    } 
    else if (strcmp(argv[1], "status") == 0) {
        // Check if daemon is running
        pid_t pid = get_daemon_pid();
        
        if (pid > 0) {
            printf("Daemon is running with PID: %d\n", pid);
        } else {
            printf("Daemon is not running\n");
            return 1;
        }
    }
    else if (strcmp(argv[1], "signal") == 0) {
        if (argc < 3) {
            printf("Error: Missing signal type\n");
            printf("Usage: %s signal [backup|reload]\n", argv[0]);
            return 1;
        }
        
        pid_t daemon_pid = get_daemon_pid();
        
        if (daemon_pid <= 0) {
            printf("Error: Daemon is not running\n");
            return 1;
        }
        
        if (strcmp(argv[2], "backup") == 0) {
            // Send SIGUSR1 to trigger backup/transfer
            if (kill(daemon_pid, SIGUSR1) == 0) {
                printf("Signal sent to daemon (PID: %d) to perform backup/transfer\n", daemon_pid);
            } else {
                printf("Error sending signal to daemon\n");
                return 1;
            }
        } else if (strcmp(argv[2], "reload") == 0) {
            // Send SIGHUP to reload configuration
            if (kill(daemon_pid, SIGHUP) == 0) {
                printf("Signal sent to daemon (PID: %d) to reload configuration\n", daemon_pid);
            } else {
                printf("Error sending signal to daemon\n");
                return 1;
            }
        } else {
            printf("Unknown signal command: %s\n", argv[2]);
            return 1;
        }
    } 
    else {
        printf("Unknown command: %s\n", argv[1]);
        printf("Usage: %s [backup|status|signal <type>]\n", argv[0]);
        return 1;
    }
    
    return 0;
}