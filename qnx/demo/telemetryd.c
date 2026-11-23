/* telemetryd: a small QNX service with a real, deliberate vulnerability.
 *
 * It reads newline-terminated commands from a FIFO and answers them:
 *   READ <key>      -- read a value from its data directory
 *   LOG <text>      -- append to its log
 *   EXEC <path>     -- intended for an operator tool, but the path is not
 *                      validated: this is the bug an attacker uses.
 * Run normally it only touches its own directory; run against a crafted
 * command it tries to spawn an arbitrary binary and read /etc/shadow-like
 * files. A least-privilege policy must make the second case fail.
 */
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DATA_DIR "/var/telemetry"
#define FIFO_PATH DATA_DIR "/ctl"
#define LOG_PATH DATA_DIR "/telemetry.log"

static int append_log(const char *text) {
    int fd = open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0640);
    if (fd < 0) return -1;
    ssize_t w1 = write(fd, text, strlen(text));
    ssize_t w2 = write(fd, "\n", 1);
    return (close(fd) == 0 && w1 >= 0 && w2 == 1) ? 0 : -1;
}

static int read_key(const char *key) {
    char path[1200], buf[256];
    snprintf(path, sizeof path, DATA_DIR "/%s", key);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("ERR %s: %s\n", key, strerror(errno)); return -1; }
    ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n < 0) { close(fd); return -1; }
    buf[n] = '\0';
    printf("OK %s=%s", key, buf);
    close(fd);
    return 0;
}

/* The vulnerability: an operator hook that spawns whatever it is given. */
static int run_tool(const char *path) {
    extern char **environ;
    char *argv[] = { (char *)path, NULL };
    pid_t pid;
    int rc = posix_spawn(&pid, path, NULL, NULL, argv, environ);
    if (rc != 0) { printf("ERR exec %s: %s\n", path, strerror(rc)); return -1; }
    printf("OK exec %s pid=%d\n", path, (int)pid);
    return 0;
}

static void handle(char *line) {
    char *nl = strchr(line, '\n');
    if (nl) *nl = '\0';
    if (!strncmp(line, "READ ", 5)) read_key(line + 5);
    else if (!strncmp(line, "LOG ", 4)) { append_log(line + 4); printf("OK log\n"); }
    else if (!strncmp(line, "EXEC ", 5)) run_tool(line + 5);
    else if (*line) printf("ERR unknown command\n");
    fflush(stdout);
}

int main(void) {
    char line[1024];
    mkdir(DATA_DIR, 0750);
    if (mkfifo(FIFO_PATH, 0620) != 0 && errno != EEXIST) {
        perror("mkfifo");
        return 1;
    }
    append_log("telemetryd started");
    printf("telemetryd ready on %s\n", FIFO_PATH);
    fflush(stdout);
    for (;;) {
        FILE *f = fopen(FIFO_PATH, "r");
        if (!f) { perror("fopen"); return 1; }
        while (fgets(line, sizeof line, f)) handle(line);
        fclose(f);
    }
}
