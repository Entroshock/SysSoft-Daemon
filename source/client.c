// client.c - Client program to send commands to the daemon
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

int main(int argc, char *argv[]) {
    // Check for correct usage
    if (argc != 2 || (strcmp(argv[1], "backup") != 0 && strcmp(argv[1], "status") != 0)) {
        printf("Usage: %s [backup|status]\n", argv[0]);
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
    } else if (strcmp(argv[1], "status") == 0) {
        // Check if daemon is running
        FILE *fp = popen("pgrep manufacturing_daemon", "r");
        char buf[32];
        
        if (fp == NULL) {
            printf("Error: Could not check daemon status\n");
            return 1;
        }
        
        if (fgets(buf, sizeof(buf), fp) != NULL) {
            printf("Daemon is running with PID: %s", buf);
        } else {
            printf("Daemon is not running\n");
        }
        
        pclose(fp);
    }
    
    return 0;
}